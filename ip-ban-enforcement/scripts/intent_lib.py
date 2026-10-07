#!/usr/bin/env python3
"""
intent_lib.py — 网络威胁意图分析核心库
判定模型：规则权重 + 行为特征加权得分 → 最高分占比判定意图 + 置信度

意图类别: recon(侦察扫描) / brute(暴力破解) / exploit(定向攻击) / botnet(僵尸网络) / abuse(爬虫CC滥用)
配置: knowledge/intent_rules.yaml（找不到时用内联默认）

被 intent_analysis.py（B: 独立画像报告）与 ip_ban_sync.py（A: 封禁打标）共用。
"""

import os, re, sqlite3, gzip
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

UTC+8 = timezone(timedelta(hours=8))
SCRIPT_DIR = Path(__file__).resolve().parent

# ─── 配置加载 ───────────────────────────────────────
def _find_knowledge_dir():
    cands = [
        SCRIPT_DIR / "knowledge",
        SCRIPT_DIR.parent / "skills" / "devops" / "ip-ban-enforcement" / "knowledge",
        Path.home() / ".hermes" / "skills" / "devops" / "ip-ban-enforcement" / "knowledge",
    ]
    for c in cands:
        if c.is_dir():
            return c
    return None

KNOWLEDGE_DIR = _find_knowledge_dir()

try:
    import yaml as _yaml
    def _load_yaml(path):
        if not path.exists(): return {}
        return _yaml.safe_load(path.read_text()) or {}
except ImportError:
    def _load_yaml(path):
        result = {}
        if not path.exists(): return result
        stack = [result]
        indent_stack = [-1]
        for line in path.read_text().splitlines():
            if not line.strip() or line.strip().startswith('#'): continue
            indent = len(line) - len(line.lstrip(' '))
            while indent <= indent_stack[-1]:
                stack.pop(); indent_stack.pop()
            content = line.strip()
            if content.startswith('- '):
                item = content[2:].strip().strip('"').strip("'")
                lst = stack[-1].setdefault('__list__', [])
                if not isinstance(lst, list): lst = []
                lst.append(item); stack[-1]['__list__'] = lst
            elif ':' in content:
                k, _, v = content.partition(':')
                k = k.strip(); v = v.strip().strip('"').strip("'")
                if v:
                    stack[-1][k] = v
                else:
                    nxt = {} if not isinstance(stack[-1].get(k), dict) else stack[-1][k]
                    stack[-1][k] = nxt
                    stack.append(nxt); indent_stack.append(indent)
        return result

def _get(data, *keys, default=None):
    v = data
    for k in keys:
        if not isinstance(v, dict) or k not in v: return default
        v = v[k]
    return v

def load_intent_rules():
    """加载意图配置，找不到文件时用内联默认。"""
    defaults = {
        "intent_categories": {
            "recon":   {"label": "🕵️ 侦察扫描",   "action": "封禁观察（30天老化自动清理）"},
            "brute":   {"label": "💥 暴力破解",   "action": "长封 + fail2ban 联动"},
            "exploit": {"label": "🎯 定向攻击",   "action": "永久封 + 溯源分析 + 升级监控"},
            "botnet":  {"label": "🤖 僵尸网络",   "action": "子网段/ASN 级拦截"},
            "abuse":   {"label": "🕷️ 爬虫/CC滥用", "action": "短封即可（CC 规则已限速）"},
        },
        "rule_intent_weights": {
            "unknownWebsite":  {"recon": 2, "botnet": 1},
            "notFoundCount":   {"recon": 2},
            "dirFilter":       {"recon": 3},
            "scannerFilter":   {"recon": 3, "botnet": 1},
            "defaultUrlBlack": {"recon": 1},
            "defaultUaBlack":  {"botnet": 3, "recon": 1},
            "attackCount":     {"brute": 2, "abuse": 1},
            "defaultIpBlack":  {"botnet": 2, "recon": 1},
            "sql":             {"exploit": 4, "brute": 1},
            "xss":             {"exploit": 4},
            "oneWordTrojan":   {"exploit": 5},
            "appFilter":       {"exploit": 3, "recon": 1},
            "args":            {"exploit": 2},
        },
        "behavior_weights": {
            "ssh_found_high":    {"brute": 3},
            "ssh_found_persist": {"brute": 2},
            "uri_wide":          {"recon": 2},
            "uri_narrow_repeat": {"brute": 2, "exploit": 1},
            "high_freq":         {"brute": 1, "abuse": 1},
            "low_freq_precise":  {"exploit": 2},
            "tls_junk":          {"recon": 2},
            "scan_ua":           {"recon": 2, "botnet": 1},
        },
        "thresholds": {
            "min_score": 3, "dominance_ratio": 0.50, "window_days": 7,
            "ssh_found_threshold": 5, "uri_wide_threshold": 20,
            "high_freq_threshold": 100, "top_n": 15,
        },
        "scanner_ua_patterns": [
            "masscan","zgrab","nmap","nikto","sqlmap","python-requests",
            "curl/","wget","go-http-client","scanner","fofa","censys",
            "shodan","majestic-12","semrush","ahrefs",
        ],
        "disposition_priority": {"exploit": 5, "brute": 4, "botnet": 3, "recon": 2, "abuse": 1, "unknown": 0},
    }
    if KNOWLEDGE_DIR:
        fp = KNOWLEDGE_DIR / "intent_rules.yaml"
        if fp.exists():
            d = _load_yaml(fp)
            for k in defaults:
                if k in d and d[k]: defaults[k] = d[k]
    return defaults

RULES = load_intent_rules()

def intent_category_label(intent):
    return RULES["intent_categories"].get(intent, {}).get("label", intent)

def intent_action(intent):
    return RULES["intent_categories"].get(intent, {}).get("action", "")

# ─── 数据采集 ───────────────────────────────────────
def get_attack_rules_for_ips(window_hours=168):
    """
    从 attack_logs.db 读最近 N 小时每个 IP 的规则命中。
    返回: {ip: {rule: count}}（rules + rule_types 双维度）
    """
    db_dir = "/var/lib/waf/"
    attack_db = os.path.join(db_dir, "attack_logs.db")
    if not os.path.exists(attack_db): return {}
    try:
        cut = (datetime.now() - timedelta(hours=window_hours)).strftime("%Y-%m-%d %H:%M:%S")
        c = sqlite3.connect(f"file:{attack_db}?mode=ro", uri=True)
        c.execute("ATTACH DATABASE ? AS r", (os.path.join(db_dir, "rules.db"),))
        c.execute("ATTACH DATABASE ? AS t", (os.path.join(db_dir, "rule_types.db"),))
        c.execute("ATTACH DATABASE ? AS i", (os.path.join(db_dir, "ips.db"),))
        rows = c.execute("""
            SELECT i.ips.value AS ip,
                   r.rules.value AS r_rule,
                   t.rule_types.value AS t_rule,
                   COUNT(*) AS cnt
            FROM attack_logs a
            JOIN i.ips ON a.ip_id = i.ips.id
            LEFT JOIN r.rules ON a.rule_id = r.rules.id
            LEFT JOIN t.rule_types ON a.rule_type_id = t.rule_types.id
            WHERE a.localtime >= ?
            GROUP BY a.ip_id, a.rule_id, a.rule_type_id
        """, (cut,)).fetchall()
        c.close()
        result = {}
        for ip, r_rule, t_rule, cnt in rows:
            if not ip or ip.count(".") != 3: continue
            for name in (r_rule, t_rule):
                if name: result.setdefault(ip, {})[name] = result.get(ip, {}).get(name, 0) + cnt
        return result
    except Exception:
        return {}

_ACCESS_LOG = "/var/log/nginx/access.log"

# 一次遍历 access.log 聚合所有目标 IP 的行为（O(日志行数)，避免 O(IP×行数)）
def collect_access_behaviors_all(target_ips, window_days=None, access_log=None):
    """
    批量采集：单次遍历 access.log，聚合 target_ips 中每个 IP 的行为特征。
    返回: {ip: {"uris": N, "reqs": N, "days": N, "tls_junk": bool, "scan_ua": bool,
                "narrow_uri": str, "narrow_cnt": N}}
    """
    if window_days is None: window_days = RULES["thresholds"]["window_days"]
    access_log = access_log or _ACCESS_LOG
    if not target_ips: return {}
    target_ips = set(target_ips)
    acc = {ip: {"uris": set(), "days": set(), "reqs": 0, "tls_junk": False, "scan_ua": False,
                "uri_counter": Counter()} for ip in target_ips}
    since = datetime.now(UTC+8) - timedelta(days=window_days)
    pat = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" \d+ \S+ "[^"]*" "([^"]*)"')
    try:
        for path in [access_log, access_log + ".1"]:
            if not os.path.exists(path): continue
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", errors="replace") as f:
                for line in f:
                    m = pat.match(line)
                    if not m: continue
                    lip, ts, method, uri, ua = m.groups()
                    if lip not in acc: continue
                    a = acc[lip]
                    try:
                        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
                    except: continue
                    if dt < since: continue
                    a["reqs"] += 1
                    a["days"].add(dt.strftime("%Y-%m-%d"))
                    if uri.startswith("\\x16") or ("\\x16\\x03" in line[:40]):
                        a["tls_junk"] = True
                    if uri.startswith("/"):
                        a["uris"].add(uri)
                        a["uri_counter"][uri] += 1
                    ual = ua.lower()
                    if any(p in ual for p in RULES["scanner_ua_patterns"]):
                        a["scan_ua"] = True
    except: pass
    result = {}
    for ip, a in acc.items():
        narrow_uri = a["uri_counter"].most_common(1)[0][0] if a["uri_counter"] else None
        result[ip] = {
            "uris": len(a["uris"]), "reqs": a["reqs"], "days": len(a["days"]),
            "tls_junk": a["tls_junk"], "scan_ua": a["scan_ua"],
            "narrow_uri": narrow_uri, "narrow_cnt": a["uri_counter"][narrow_uri] if narrow_uri else 0,
        }
    return result

def get_access_behaviors(ip, window_days=None, access_log=None):
    """单 IP 采集（兼容接口，内部走批量实现）。"""
    if window_days is None: window_days = RULES["thresholds"]["window_days"]
    access_log = access_log or _ACCESS_LOG
    return collect_access_behaviors_all({ip}, window_days=window_days, access_log=access_log).get(ip, {
        "uris": 0, "reqs": 0, "days": 0, "tls_junk": False, "scan_ua": False,
        "narrow_uri": None, "narrow_cnt": 0})

def get_ssh_found_count(ip, window_days=None):
    """从 fail2ban.log 统计 SSH Found 次数和跨天数。返回 (count, days)。"""
    if window_days is None: window_days = RULES["thresholds"]["window_days"]
    ef = [f for f in ["/var/log/fail2ban.log","/var/log/fail2ban.log.1",
                      "/var/log/fail2ban.log.2.gz","/var/log/fail2ban.log.3.gz"] if os.path.exists(f)]
    if not ef: return 0, 0
    cnt, days = 0, set()
    try:
        r = subprocess_run(["zgrep","-h",r"\[sshd\].*Found "+re.escape(ip),*ef])
        for l in r.splitlines():
            m = re.match(r"(\d{4}-\d{2}-\d{2})", l)
            if m: days.add(m.group(1)); cnt += 1
    except: return 0, 0
    return cnt, len(days)

import subprocess as _sp
def subprocess_run(cmd, timeout=30):
    r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()

# ─── 意图评分与判定 ─────────────────────────────────
def classify_intent(rule_hits=None, behaviors=None):
    """
    核心判定：聚合规则命中 + 行为特征 → 各意图得分 → 判定。
    入参:
      rule_hits: {rule: count}  — WAF 规则命中
      behaviors: dict           — get_access_behaviors/get_ssh_found_count 结果合并
    返回:
      {intent, score, total, confidence, breakdown: {intent: score}, features: [str]}
    """
    rule_hits = rule_hits or {}
    behaviors = behaviors or {}
    th = RULES["thresholds"]
    scores = Counter()
    features = []

    # 1. 规则权重累加
    for rule, cnt in rule_hits.items():
        w = RULES["rule_intent_weights"].get(rule)
        if not w: continue
        for intent, wt in w.items():
            scores[intent] += wt * min(cnt, 5)  # 单规则封顶×5，防单点刷爆
    if rule_hits:
        top_rule = max(rule_hits, key=rule_hits.get)
        features.append(f"规则:{top_rule}×{rule_hits[top_rule]}")

    # 2. 行为特征加分
    ssh_cnt = behaviors.get("ssh_cnt", 0)
    if ssh_cnt >= th["ssh_found_threshold"]:
        for intent, wt in RULES["behavior_weights"]["ssh_found_high"].items():
            scores[intent] += wt
        features.append(f"SSH失败{ssh_cnt}次")
    if behaviors.get("ssh_days", 0) >= 2:
        for intent, wt in RULES["behavior_weights"]["ssh_found_persist"].items():
            scores[intent] += wt
        features.append(f"SSH跨{behaviors['ssh_days']}天")

    uris = behaviors.get("uris", 0)
    if uris >= th["uri_wide_threshold"]:
        for intent, wt in RULES["behavior_weights"]["uri_wide"].items():
            scores[intent] += wt
        features.append(f"触碰{uris}个URI")
    narrow_cnt = behaviors.get("narrow_cnt", 0)
    if narrow_cnt >= 5 and uris <= 3:
        for intent, wt in RULES["behavior_weights"]["uri_narrow_repeat"].items():
            scores[intent] += wt
        features.append(f"反复打{behaviors.get('narrow_uri','?')}×{narrow_cnt}")

    reqs = behaviors.get("reqs", 0)
    if reqs >= th["high_freq_threshold"]:
        for intent, wt in RULES["behavior_weights"]["high_freq"].items():
            scores[intent] += wt
        features.append(f"高频{reqs}次")
    if behaviors.get("low_freq_precise"):
        for intent, wt in RULES["behavior_weights"]["low_freq_precise"].items():
            scores[intent] += wt
        features.append("低频精准")
    if behaviors.get("tls_junk"):
        for intent, wt in RULES["behavior_weights"]["tls_junk"].items():
            scores[intent] += wt
        features.append("TLS握手打HTTP")
    if behaviors.get("scan_ua"):
        for intent, wt in RULES["behavior_weights"]["scan_ua"].items():
            scores[intent] += wt
        features.append("扫描器UA")

    total = sum(scores.values())
    if total < th["min_score"]:
        return {"intent": "unknown", "score": 0, "total": total, "confidence": 0.0,
                "breakdown": dict(scores), "features": features}

    top_intent, top_score = scores.most_common(1)[0]
    ratio = top_score / total
    if ratio >= th["dominance_ratio"]:
        intent = top_intent
    else:
        # 混合意图：取 top2 显示
        ranked = scores.most_common(2)
        intent = "mixed:" + "+".join(i for i, _ in ranked)
    return {"intent": intent, "score": top_score, "total": total,
            "confidence": round(ratio, 2), "breakdown": dict(scores),
            "features": features}

def analyze_ip(ip, window_hours=168, include_access=True, behaviors=None):
    """
    一站式分析单个 IP：采集 attack_logs + access.log + fail2ban → 判定意图。
    入参 behaviors: 预采集的行为数据（批量模式下传入，跳过重复日志扫描）。
    返回: {ip, intent, confidence, breakdown, features, rules, behaviors}
    """
    rule_map = get_attack_rules_for_ips(window_hours).get(ip, {})
    if behaviors is None:
        behaviors = {}
        if include_access:
            ab = get_access_behaviors(ip)
            behaviors.update({k: v for k, v in ab.items() if k != "narrow_uri"})
            behaviors["narrow_uri"] = ab.get("narrow_uri")
            behaviors["narrow_cnt"] = ab.get("narrow_cnt", 0)
        ssh_cnt, ssh_days = get_ssh_found_count(ip)
        behaviors["ssh_cnt"], behaviors["ssh_days"] = ssh_cnt, ssh_days
    res = classify_intent(rule_map, behaviors)
    res["ip"] = ip
    res["rules"] = rule_map
    res["behaviors"] = behaviors
    return res

if __name__ == "__main__":
    # 自测：直接跑 python3 intent_lib.py <IP>
    import sys, json
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    if ip:
        r = analyze_ip(ip)
        print(json.dumps(r, ensure_ascii=False, indent=2, default=str))
    else:
        print("用法: python3 intent_lib.py <IP>")
