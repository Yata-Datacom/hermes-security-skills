#!/usr/bin/env python3
"""
ip_ban_sync.py — IP 封禁同步 + 攻击类型感知 + IPS 签名检测
用法: python3 ip_ban_sync.py [sync|daily|ips|analyze|report]

模式:
  sync (默认): 每周同步 — fail2ban/WAF/攻击日志分级/低频SSH/子网段 → PERMA-BAN
  daily:       每日增量 — 仅扫最近24h攻击日志，高危即封（D 方向）
  ips:         IPS 签名检测 — 扫 access.log 匹配 SQLi/XSS/路径穿越/Webshell 签名（E 方向）
  analyze:     GeoIP 分布 + 去重 + Bulletproof + 住宅ISP + 老化验证
  report:      当前状态和趋势（只读）

配置: knowledge/*.yaml（skill 目录），找不到时用内联默认值。
"""

import subprocess, sqlite3, sys, re, json, os, time, urllib.request, gzip
from datetime import datetime, timezone, timedelta
from collections import Counter
from pathlib import Path

UTC+8 = timezone(timedelta(hours=8))
SCRIPT_DIR = Path(__file__).resolve().parent

# ─── 意图分析集成（A 方案：封禁时打意图标签） ──────
try:
    sys.path.insert(0, str(SCRIPT_DIR))
    from intent_lib import classify_intent, collect_access_behaviors_all
    INTENT_AVAILABLE = True
except ImportError:
    INTENT_AVAILABLE = False

# ─── 配置加载（knowledge/ 优先，找不到回退内联默认） ───
def _find_knowledge_dir():
    """从脚本位置向上找 knowledge/ 配置目录。"""
    cands = [
        SCRIPT_DIR / "knowledge",                                  # 直接在 skill 目录内跑
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
    # 简单缩进解析器 fallback（无 PyYAML 环境）
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

def _load_threshold(*keys, default=None):
    if KNOWLEDGE_DIR:
        data = _load_yaml(KNOWLEDGE_DIR / "thresholds.yaml")
        return _get(data, *keys, default=default)
    return default

def _load_patterns(name):
    if KNOWLEDGE_DIR:
        fp = KNOWLEDGE_DIR / (name + ".yaml")
        return _load_yaml(fp).get('patterns', []) if fp.exists() else None
    return None

def _load_subnets():
    if KNOWLEDGE_DIR:
        fp = KNOWLEDGE_DIR / "subnets.yaml"
        if fp.exists():
            data = _load_yaml(fp)
            return [(s.get('subnet',''), s.get('comment','')) for s in data.get('subnets', []) if isinstance(s, dict)]
    return None

def _load_attack_rules():
    if KNOWLEDGE_DIR:
        fp = KNOWLEDGE_DIR / "attack_rules.yaml"
        if fp.exists():
            d = _load_yaml(fp)
            return {
                "high": d.get("high_risk", []), "medium": d.get("medium_risk", []), "low": d.get("low_risk", []),
                "high_min_hits": _get(d, "thresholds", "high_min_hits", default=1),
                "high_window_days": _get(d, "thresholds", "high_window_days", default=7),
                "medium_min_hits": _get(d, "thresholds", "medium_min_hits", default=10),
                "daily_window_hours": _get(d, "thresholds", "daily_window_hours", default=24),
            }
    return {"high": ["sql","xss","oneWordTrojan"], "medium": ["dirFilter","scannerFilter","appFilter","args"],
            "low": ["unknownWebsite","notFoundCount","defaultUrlBlack","defaultUaBlack","attackCount","defaultIpBlack"],
            "high_min_hits": 1, "high_window_days": 7, "medium_min_hits": 10, "daily_window_hours": 24}

def _load_signatures():
    if KNOWLEDGE_DIR:
        fp = KNOWLEDGE_DIR / "attack_signatures.yaml"
        if fp.exists():
            d = _load_yaml(fp)
            sigs = {k: [s.lower() for s in v] for k, v in d.items() if isinstance(v, list)}
            return sigs, _get(d, "thresholds", "min_hits", default=2), _get(d, "thresholds", "window_days", default=7)
    return {}, 2, 7

# ─── 核心配置 ───────────────────────────────────────
CACHE_DIR = os.path.expanduser("~/.hermes/cache")
GEO_CACHE_FILE = os.path.expanduser(_load_threshold('cache','geoip', default="~/.hermes/cache/geoip_cache.json"))
SYNC_HISTORY_FILE = os.path.expanduser(_load_threshold('cache','sync_history', default="~/.hermes/cache/sync_history.json"))
WAF_BLOCK_DB = _load_threshold('waf','block_db', default="/var/lib/waf/block_ips.db")
WAF_IPS_DB = _load_threshold('waf','ips_db', default="/var/lib/waf/ips.db")
WAF_ATTACK_DB = _load_threshold('waf','attack_db', default="/var/lib/waf/attack_logs.db")
WAF_RULES_DB = os.path.join(os.path.dirname(WAF_ATTACK_DB), "rules.db")
WAF_TYPES_DB = os.path.join(os.path.dirname(WAF_ATTACK_DB), "rule_types.db")
ACCESS_LOG = _load_threshold('waf','access_log', default="/var/log/nginx/access.log")
WEEKLY_SCAN_THRESHOLD = _load_threshold('thresholds','weekly_scan', default=10)
OLD_THRESHOLD_DAYS = _load_threshold('thresholds','old_days', default=30)
MAX_GEO_BATCH = _load_threshold('thresholds','max_geo_batch', default=45)

_wl = _load_threshold('whitelist','ips', default=["203.0.113.10","100.64.0.1","127.0.0.1"])
WHITELIST_IPS = set(_wl)
WHITELIST_SUBNETS = _load_threshold('whitelist','subnets', default=["100.64.0.0/10","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])

RESIDENTIAL_ISP_PATTERNS = _load_patterns('residential_isp') or [
    "chinanet","china telecom","中国电信","chinaunicom","china unicom","中国联通",
    "chinamobile","china mobile","中国移动","telenor","telkomsel","telkom","indihome",
    "viettel","vnpt","fpt telecom","comcast","spectrum","charter","cox","verizon",
    "deutsche telekom","telefonica","orange","bt","kddi","softbank","ntt","au one",
    "singtel","starhub","m1","tm net","unifi","time dotcom","true online","ais","dtac",
    "jio","airtel","bsnl","vodafone","swisscom","telia","beeline","megafon","mts",
]
BULLETPROOF_PATTERNS = _load_patterns('bulletproof_patterns') or [
    "power.line","powerline","as132839","techtie","dmzhost","vmheaven","scaleway",
    "kronnet","hostkey","datacheap","g-core","m247","frantech","global-layer","buyvm","greencloudvps",
]
SUBNET_BLOCKS = _load_subnets() or [
    ("203.0.113.0/24","bulletproof hosting（示例）"),("198.51.100.0/24","bulletproof hosting（示例）"),
    ("192.0.2.0/24","bulletproof hosting（示例）"),("203.0.113.0/24","bulletproof hosting（示例）"),
    ("198.51.100.0/24","scanning infra（示例）"),("192.0.2.0/24","compromised VPS（示例）"),
    ("203.0.113.0/24","hostile host（示例）"),("198.51.100.0/24","scan VPS（示例）"),
    ("192.0.2.0/24","hostile host（示例）"),("203.0.113.0/24","proxy abuser（示例）"),
    ("198.51.100.0/24","FranTech abuser (LU/US)"),
]
ATTACK_RULES = _load_attack_rules()
SIGNATURES, SIG_MIN_HITS, SIG_WINDOW_DAYS = _load_signatures()

def in_whitelist(ip):
    if ip in WHITELIST_IPS: return True
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        for sn in WHITELIST_SUBNETS:
            if a in ipaddress.ip_network(sn): return True
    except: pass
    return False

# ─── 工具函数 ───────────────────────────────────────
def run(cmd, timeout=30):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()

def run_raw(cmd, timeout=30):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout, r.stderr, r.returncode

# ─── iptables 操作 ───────────────────────────────────
def get_perma_ban_ips():
    ips = set()
    for line in run(["iptables","-L","PERMA-BAN","-n"]).splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] == "DROP" and "/" not in p[3] and p[3] != "0.0.0.0/0" and p[3].count(".") == 3:
            ips.add(p[3])
    return ips

def get_perma_ban_subnets():
    sn = set()
    for line in run(["iptables","-L","PERMA-BAN","-n"]).splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] == "DROP" and "/" in p[3]:
            sn.add(p[3])
    return sn

def add_to_perma_ban(ip, comment=None):
    """添加单 IP 到 PERMA-BAN，可选 comment（意图标签可审计）。"""
    if comment:
        subprocess.run(["iptables","-A","PERMA-BAN","-s",ip,"-m","comment","--comment",comment,"-j","DROP"], capture_output=True, timeout=10)
    else:
        subprocess.run(["iptables","-A","PERMA-BAN","-s",ip,"-j","DROP"], capture_output=True, timeout=10)

def add_subnet(subnet, comment):
    subprocess.run(["iptables","-A","PERMA-BAN","-s",subnet,"-m","comment","--comment",comment,"-j","DROP"], capture_output=True, timeout=10)

# ─── 意图标注（A 方案） ─────────────────────────────
def annotate_intents(ips, window_hours=168):
    """
    批量给 IP 标注意图。返回 {ip: {"intent": str, "label": str, "confidence": float, "features": [str]}}
    依赖 intent_lib（同目录），缺失时返回空。
    """
    if not INTENT_AVAILABLE or not ips: return {}
    from intent_lib import RULES as _IR, analyze_ip, get_attack_rules_for_ips, intent_category_label
    ip_list = list(ips)
    rule_map = get_attack_rules_for_ips(window_hours)
    try:
        access_beh = collect_access_behaviors_all(ip_list, window_days=max(1, window_hours // 24))
    except Exception:
        access_beh = {}
    result = {}
    for ip in ip_list:
        try:
            ab = access_beh.get(ip, {})
            behaviors = dict(ab)  # narrow_uri / narrow_cnt / uris / reqs / ... 全部透传
            # SSH 统计
            ssh_cnt, ssh_days = 0, 0
            try:
                from intent_lib import get_ssh_found_count
                ssh_cnt, ssh_days = get_ssh_found_count(ip)
            except Exception: pass
            behaviors["ssh_cnt"], behaviors["ssh_days"] = ssh_cnt, ssh_days
            r = analyze_ip(ip, window_hours=window_hours, behaviors=behaviors)
            base = r["intent"].split(":")[0]
            if base == "mixed":
                label = "混合"
            else:
                label = intent_category_label(base).split(" ")[1] if base in _IR["intent_categories"] else base
            result[ip] = {
                "intent": r["intent"],
                "label": label,
                "confidence": r["confidence"],
                "features": r["features"],
            }
        except Exception:
            continue
    return result

def intent_comment(ip, ann):
    """生成 iptables comment：INTENT=<intent> <label> <date>。"""
    now = datetime.now(UTC+8).strftime("%Y-%m-%d")
    a = ann.get(ip)
    if not a: return f"ban {now}"
    return f"INTENT={a['intent'].split(':')[0]} {a['label']} {now}"

# ─── fail2ban ─────────────────────────────────────────
def get_fail2ban_ips():
    ips = set()
    s = run(["fail2ban-client","status"])
    for line in s.splitlines():
        if "Jail list:" in line:
            for j in [j.strip() for j in line.split(":",1)[1].strip().strip(",").split(",") if j.strip()]:
                js = run(["fail2ban-client","status",j])
                for l in js.splitlines():
                    if "Banned IP list:" in l:
                        for ip in l.split(":",1)[1].strip().split():
                            ip = ip.strip()
                            if ip.count(".") == 3: ips.add(ip)
    return ips

# ─── 1Panel WAF（PRAGMA 自适应） ───────────────────────
_waf_schema = None
def detect_waf_schema():
    global _waf_schema
    if _waf_schema: return _waf_schema
    schema = {}
    try:
        c = sqlite3.connect(f"file:{WAF_BLOCK_DB}?mode=ro", uri=True)
        cols = {row[1]: row[0] for row in c.execute("PRAGMA table_info(block_ips)")}; c.close()
        if "ip_id" in cols and "is_block" in cols: schema.update(block_ip_col="ip_id", block_flag_col="is_block", flag_value=1)
        elif "ip" in cols and "status" in cols: schema.update(block_ip_col="ip", block_flag_col="status", flag_value=1)
        elif "ip" in cols and "blocked" in cols: schema.update(block_ip_col="ip", block_flag_col="blocked", flag_value=1)
        else: schema["fallback"] = True
        if not schema.get("fallback") and schema.get("block_ip_col") != "ip":
            c2 = sqlite3.connect(f"file:{WAF_IPS_DB}?mode=ro", uri=True)
            ic = {row[1]: row[0] for row in c2.execute("PRAGMA table_info(ips)")}; c2.close()
            schema["ips_value_col"] = "value" if "value" in ic else ("ip" if "ip" in ic else list(ic.keys())[0])
        _waf_schema = schema; return schema
    except: return {"fallback": True}

def get_waf_blocked_ips():
    s = detect_waf_schema()
    if s.get("fallback"): return set()
    ips = set()
    try:
        ic, fc, fv = s["block_ip_col"], s["block_flag_col"], s["flag_value"]
        if ic == "ip":
            c = sqlite3.connect(f"file:{WAF_BLOCK_DB}?mode=ro", uri=True)
            rows = c.execute(f"SELECT {ic} FROM block_ips WHERE {fc}=?", (fv,)).fetchall(); c.close()
        else:
            vc = s.get("ips_value_col", "value")
            c = sqlite3.connect(f"file:{WAF_BLOCK_DB}?mode=ro", uri=True)
            c.execute("ATTACH DATABASE ? AS ips_db", (WAF_IPS_DB,))
            rows = c.execute(f"SELECT DISTINCT ips_db.ips.{vc} FROM block_ips JOIN ips_db.ips ON block_ips.{ic}=ips_db.ips.id WHERE block_ips.{fc}=?", (fv,)).fetchall(); c.close()
        for r in rows:
            ip = r[0]
            if ip and ip.count(".") == 3: ips.add(ip)
    except: pass
    return ips

# ─── 攻击日志分级读取（A 方向核心） ─────────────────
def get_attack_log_ips(window_hours=168):
    """
    读取 attack_logs.db，按规则名聚合每个 IP 的攻击次数。
    返回: {ip: {"rule": count, ...}}。rule_id 与 rule_type_id 两个维度都采集
    （同一条记录可能同时命中 rules.db 的规则名和 rule_types.db 的类型名）。
    """
    if not os.path.exists(WAF_ATTACK_DB): return {}
    try:
        cut = (datetime.now() - timedelta(hours=window_hours)).strftime("%Y-%m-%d %H:%M:%S")
        c = sqlite3.connect(f"file:{WAF_ATTACK_DB}?mode=ro", uri=True)
        c.execute("ATTACH DATABASE ? AS rules_db", (WAF_RULES_DB,))
        c.execute("ATTACH DATABASE ? AS types_db", (WAF_TYPES_DB,))
        c.execute("ATTACH DATABASE ? AS ips_db", (WAF_IPS_DB,))
        rows = c.execute("""
            SELECT ips_db.ips.value AS ip,
                   rules_db.rules.value AS r_rule,
                   types_db.rule_types.value AS t_rule,
                   COUNT(*) AS cnt
            FROM attack_logs a
            JOIN ips_db.ips ON a.ip_id = ips_db.ips.id
            LEFT JOIN rules_db.rules ON a.rule_id = rules_db.rules.id
            LEFT JOIN types_db.rule_types ON a.rule_type_id = types_db.rule_types.id
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

def classify_attacks(attack_map, min_hits_map=None):
    """
    按 ATTACK_RULES 分级。
    返回: {"high": {ip: {rule: cnt}}, "medium": {ip: {rule: cnt}}, "low": {ip: {rule: cnt}}}
    """
    high, medium, low = {}, {}, {}
    for ip, rules in attack_map.items():
        for rule, cnt in rules.items():
            if rule in ATTACK_RULES["high"]:
                if cnt >= ATTACK_RULES["high_min_hits"]: high.setdefault(ip, {})[rule] = cnt
            elif rule in ATTACK_RULES["medium"]:
                if cnt >= ATTACK_RULES["medium_min_hits"]: medium.setdefault(ip, {})[rule] = cnt
            else:
                low.setdefault(ip, {})[rule] = cnt
    return {"high": high, "medium": medium, "low": low}

# ─── 低频 SSH 扫描检测 ──────────────────────────────
def get_weekly_scanners(cutoff):
    cnt = Counter()
    ef = [f for f in ["/var/log/fail2ban.log","/var/log/fail2ban.log.1","/var/log/fail2ban.log.2.gz","/var/log/fail2ban.log.3.gz","/var/log/fail2ban.log.4.gz"] if os.path.exists(f)]
    if not ef: return {}
    try:
        r = subprocess.run(["zgrep","-h",r"\[sshd\].*Found",*ef], capture_output=True, text=True, timeout=60)
        if r.returncode not in (0,1): return {}
        for l in r.stdout.splitlines():
            m = re.match(r"(\d{4}-\d{2}-\d{2})", l)
            if m and m.group(1) >= cutoff:
                im = re.search(r"Found (\d+\.\d+\.\d+\.\d+)", l)
                if im: cnt[im.group(1)] += 1
    except: return {}
    return {ip: c for ip, c in cnt.items() if c >= WEEKLY_SCAN_THRESHOLD}

# ─── IPS 签名检测（E 方向核心） ────────────────────
def parse_access_log(log_file, since_dt=None):
    """解析 combined 格式 access.log，返回 [(ip, uri, ua, status, dt), ...]"""
    entries = []
    pat = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) \S+ "([^"]*)" "([^"]*)"')
    try:
        for path in [log_file, log_file + ".1"]:
            if not os.path.exists(path): continue
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", errors="replace") as f:
                for line in f:
                    m = pat.match(line)
                    if not m: continue
                    ip, ts, method, uri, status, ref, ua = m.groups()
                    try:
                        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
                    except: continue
                    if since_dt and dt < since_dt: continue
                    entries.append((ip, uri, ua, int(status), dt))
    except: pass
    return entries

def ips_signature_detect(window_days=7):
    """
    扫描 access.log，匹配攻击签名。
    返回: {"ip": {"category": count}}
    """
    if not SIGNATURES or not os.path.exists(ACCESS_LOG): return {}
    since = datetime.now(UTC+8) - timedelta(days=window_days)
    hits = {}  # ip -> {category: count}
    for ip, uri, ua, status, dt in parse_access_log(ACCESS_LOG, since):
        blob = f"{uri} {ua}".lower()
        # URL 解码后二次匹配（捕获 %2e%2e 这类编码）
        try:
            from urllib.parse import unquote
            blob += " " + unquote(uri).lower()
        except: pass
        for cat, sigs in SIGNATURES.items():
            if cat == "thresholds": continue
            for sig in sigs:
                if sig in blob:
                    hits.setdefault(ip, {}).setdefault(cat, 0)
                    hits[ip][cat] += 1
                    break  # 每类每请求只记一次
    return hits

# ─── GeoIP 缓存 ───────────────────────────────────────
def load_geo_cache():
    if os.path.exists(GEO_CACHE_FILE):
        try: return json.load(open(GEO_CACHE_FILE))
        except: pass
    return {}

def save_geo_cache(cache):
    os.makedirs(CACHE_DIR, exist_ok=True)
    t = GEO_CACHE_FILE + ".tmp"; json.dump(cache, open(t, "w"), indent=2); os.replace(t, GEO_CACHE_FILE)

def geo_lookup(ips):
    cache = load_geo_cache(); results = {}
    unc = [ip for ip in ips if ip not in cache]
    if unc:
        for bs in range(0, len(unc), MAX_GEO_BATCH):
            batch = unc[bs:bs+MAX_GEO_BATCH]
            try:
                d = json.dumps(batch).encode()
                req = urllib.request.Request("http://ip-api.com/batch", data=d, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    for rr in json.loads(r.read()):
                        if rr.get("status") == "success":
                            cache[rr["query"]] = {"country": rr.get("country","?"), "countryCode": rr.get("countryCode","?"), "isp": rr.get("isp","?"), "as": rr.get("as","?"), "org": rr.get("org","?")}
            except: pass
        save_geo_cache(cache)
    for ip in ips:
        if ip in cache: results[ip] = cache[ip]
    return results

def is_residential(g):
    if not g: return False
    t = f"{g.get('isp','')} {g.get('org','')}".lower()
    return any(p in t for p in RESIDENTIAL_ISP_PATTERNS)

def is_bulletproof(g):
    if not g: return False
    t = f"{g.get('as','')} {g.get('org','')}".lower()
    return any(p in t for p in BULLETPROOF_PATTERNS)

def check_ip_still_active(ip, db=7):
    cut = (datetime.now()-timedelta(days=db)).strftime("%Y-%m-%d")
    ef = [f for f in ["/var/log/auth.log","/var/log/auth.log.1"] if os.path.exists(f)]
    if not ef: return False
    r = subprocess.run(["zgrep","-h",ip,*ef], capture_output=True, text=True, timeout=30)
    if r.returncode not in (0,1): return False
    for l in r.stdout.splitlines():
        m = re.match(r"(\d{4}-\d{2}-\d{2})", l)
        if m and m.group(1) >= cut: return True
    return False

def load_history():
    if os.path.exists(SYNC_HISTORY_FILE):
        try: return json.load(open(SYNC_HISTORY_FILE))
        except: pass
    return []

def save_history(e):
    h = load_history(); h.append(e)
    if len(h) > 52: h = h[-52:]
    os.makedirs(CACHE_DIR, exist_ok=True)
    t = SYNC_HISTORY_FILE + ".tmp"; json.dump(h, open(t, "w"), indent=2); os.replace(t, SYNC_HISTORY_FILE)
    return h

# ─── 核心同步（sync 每周 / daily 每日共用） ─────────
def _ban_new_ips(all_new, pi, sc, buf, log, annotate=True):
    """批量添加新 IP 到 PERMA-BAN 并验证。annotate=True 时带意图注释。"""
    if not all_new:
        log("   ✨ 无新 IP"); return []
    ann = annotate_intents(all_new) if (annotate and INTENT_AVAILABLE) else {}
    if ann:
        log("   🎯 意图标注完成")
    for ip in sorted(all_new):
        add_to_perma_ban(ip, comment=intent_comment(ip, ann))
    pn = get_perma_ban_ips()
    ad = [ip for ip in sorted(all_new) if ip in pn]
    fl = [ip for ip in sorted(all_new) if ip not in pn]
    for ip in ad:
        tag = f" [低频 {sc[ip]}次/7天]" if ip in sc else ""
        intag = f" 🎯{ann[ip]['label']}({int(ann[ip]['confidence']*100)}%)" if ip in ann else ""
        log(f"   ✅ {ip}{tag}{intag}")
    for ip in fl: log(f"   ❌ {ip} — 添加失败")
    if ad:
        _,_,rc = run_raw(["netfilter-persistent","save"])
        log(f"💾 保存: {'成功' if rc==0 else '⚠️ 失败'}")
    return ad

def do_sync():
    """每周全量同步：fail2ban + WAF + 攻击日志分级 + 低频SSH + 子网段"""
    now = datetime.now(UTC+8); ns = now.strftime("%Y-%m-%d %H:%M:%S")
    cut = (now-timedelta(days=7)).strftime("%Y-%m-%d")
    buf = []
    def log(s=""): print(s); buf.append(s)

    log(f"🛡️ IP 封禁同步报告 — {ns} UTC+8")
    log("=" * 50)
    pi, ps = get_perma_ban_ips(), get_perma_ban_subnets()
    log(f"\n📋 PERMA-BAN 已有: {len(pi)} IP + {len(ps)} 子网段")

    f2b = get_fail2ban_ips(); nf = f2b - pi
    log(f"🔒 fail2ban 当前封禁: {len(f2b)} IP (新: {len(nf)})")

    waf = get_waf_blocked_ips(); nw = waf - pi
    log(f"🛡️ WAF 当前封禁: {len(waf)} IP (新: {len(nw)})")

    # A: 攻击日志分级（7天窗口）
    att = get_attack_log_ips(168)
    cls = classify_attacks(att)
    nh = set(cls["high"].keys()) - pi
    nm = set(cls["medium"].keys()) - pi
    log(f"\n🎯 攻击日志 (7天): 高危 {len(cls['high'])} (新{len(nh)}) | 中危 {len(cls['medium'])} (新{len(nm)})")
    for ip in sorted(cls["high"], key=lambda x: max(cls["high"][x].values()), reverse=True)[:8]:
        rl = ",".join(f"{r}×{c}" for r, c in sorted(cls["high"][ip].items()))
        log(f"   🔴 {ip} — {rl} {'✅' if ip in pi else '🆕'}")
    for ip in sorted(cls["medium"], key=lambda x: max(cls["medium"][x].values()), reverse=True)[:5]:
        rl = ",".join(f"{r}×{c}" for r, c in sorted(cls["medium"][ip].items()))
        log(f"   🟡 {ip} — {rl} {'✅' if ip in pi else '🆕'}")

    # B: Web 扫描（中危已含）+ 低频 SSH
    sc = get_weekly_scanners(cut); nsc = set(sc.keys()) - pi
    log(f"\n🔎 低频SSH (7天≥{WEEKLY_SCAN_THRESHOLD}次): {len(sc)} IP (新: {len(nsc)})")
    for ip in sorted(sc, key=sc.get, reverse=True)[:5]:
        log(f"   {ip} — {sc[ip]}次 {'✅' if ip in pi else '🆕'}")

    # 子网段
    es = sum(1 for s,_ in SUBNET_BLOCKS if s in ps)
    ne = [(s,c) for s,c in SUBNET_BLOCKS if s not in ps]
    log(f"\n🌐 恶意子网段 ({len(SUBNET_BLOCKS)}): {es} 已拦截, {len(ne)} 待添加")
    for s, c in ne:
        add_subnet(s, c)
        log(f"   {'✅' if s in get_perma_ban_subnets() else '❌'} {s} — {c}")

    all_new = (nf | nw | nh | nm | nsc) - WHITELIST_IPS
    wh_hits = (nf | nw | nh | nm | nsc) & WHITELIST_IPS
    if wh_hits:
        log(f"\n⚪ 白名单跳过: {', '.join(sorted(wh_hits))}")
    if all_new:
        src = []
        for name, s in [("fail2ban",nf),("WAF",nw),("攻击高危",nh),("攻击中危",nm),("低频SSH",nsc)]:
            if s & all_new: src.append(name)
        log(f"\n🚨 {len(all_new)} 个新 IP ({', '.join(src)}) 加入 PERMA-BAN…")
    ad = _ban_new_ips(all_new, pi, sc, buf, log)
    log(f"\n📊 汇总：新增 {len(ad)} IP + {len(ne)} 子网段")

    fi, fs = len(get_perma_ban_ips()), len(get_perma_ban_subnets())
    log(f"\n🔢 PERMA-BAN 最终: {fi} IP + {fs} 子网段")
    hist = save_history({"date": now.strftime("%Y-%m-%d"), "time": ns, "new_ips": len(all_new), "new_subnets": len(ne), "total_ips": fi, "total_subnets": fs, "attack_high": len(cls["high"]), "attack_medium": len(cls["medium"])})
    if len(hist) >= 2:
        p = hist[-2]
        log(f"\n📈 趋势 (vs {p.get('date','上周')}): IP {fi-p.get('total_ips',fi):+d} {'📈' if fi>p.get('total_ips',fi) else '📉' if fi<p.get('total_ips',fi) else ''}")
    return "\n".join(buf)

def do_daily():
    """每日增量：仅扫最近 N 小时攻击日志，高危即封（D 方向）"""
    now = datetime.now(UTC+8); ns = now.strftime("%Y-%m-%d %H:%M:%S")
    hrs = ATTACK_RULES["daily_window_hours"]
    buf = []
    def log(s=""): print(s); buf.append(s)

    log(f"⚡ 每日攻击增量 — {ns} UTC+8 (窗口 {hrs}h)")
    log("=" * 50)
    pi, ps = get_perma_ban_ips(), get_perma_ban_subnets()

    att = get_attack_log_ips(hrs)
    cls = classify_attacks(att)
    nh = set(cls["high"].keys()) - pi
    nm = set(cls["medium"].keys()) - pi
    log(f"🎯 近{hrs}h 攻击: 高危 {len(cls['high'])} | 中危 {len(cls['medium'])}")
    for ip in sorted(cls["high"], key=lambda x: max(cls["high"][x].values()), reverse=True)[:10]:
        rl = ",".join(f"{r}×{c}" for r, c in sorted(cls["high"][ip].items()))
        log(f"   🔴 {ip} — {rl} {'✅' if ip in pi else '🆕'}")
    for ip in sorted(cls["medium"], key=lambda x: max(cls["medium"][x].values()), reverse=True)[:5]:
        rl = ",".join(f"{r}×{c}" for r, c in sorted(cls["medium"][ip].items()))
        log(f"   🟡 {ip} — {rl} {'✅' if ip in pi else '🆕'}")

    all_new = (nh | nm) - WHITELIST_IPS
    wh_hits = (nh | nm) & WHITELIST_IPS
    if wh_hits:
        log(f"\n⚪ 白名单跳过: {', '.join(sorted(wh_hits))}")
    if all_new:
        log(f"\n🚨 {len(all_new)} 个新攻击 IP 加入 PERMA-BAN…")
    ad = _ban_new_ips(all_new, pi, {}, buf, log)
    log(f"\n📊 新增 {len(ad)} IP")
    fi, fs = len(get_perma_ban_ips()), len(get_perma_ban_subnets())
    log(f"🔢 PERMA-BAN: {fi} IP + {fs} 子网段")
    save_history({"date": now.strftime("%Y-%m-%d"), "time": ns, "new_ips": len(all_new), "new_subnets": 0, "total_ips": fi, "total_subnets": fs, "mode": "daily"})
    return "\n".join(buf)

def do_ips():
    """IPS 签名检测：扫 access.log 匹配攻击签名（E 方向）"""
    now = datetime.now(UTC+8); ns = now.strftime("%Y-%m-%d %H:%M:%S")
    buf = []
    def log(s=""): print(s); buf.append(s)

    log(f"🛡️ IPS 签名检测 — {ns} UTC+8 (窗口 {SIG_WINDOW_DAYS}d)")
    log("=" * 50)
    hits = ips_signature_detect(SIG_WINDOW_DAYS)
    if not hits:
        log("无命中（或 access.log 不可读）")
        return "\n".join(buf)

    pi, ps = get_perma_ban_ips(), get_perma_ban_subnets()
    cat_cnt = Counter()
    for ip, cats in hits.items():
        for c in cats: cat_cnt[c] += 1
    log(f"\n📊 签名类别分布:")
    for c, n in cat_cnt.most_common():
        log(f"   {c:20s} {n} IP")

    # 阈值过滤：单类别 ≥ SIG_MIN_HITS 才封
    ban_map = {}
    for ip, cats in hits.items():
        for c, n in cats.items():
            if n >= SIG_MIN_HITS:
                ban_map.setdefault(ip, {})[c] = n
    new_ips = set(ban_map.keys()) - pi - WHITELIST_IPS
    wh_hits = set(ban_map.keys()) & WHITELIST_IPS
    if wh_hits:
        log(f"\n⚪ 白名单跳过: {', '.join(sorted(wh_hits))}")
    log(f"\n🚨 签名命中 {len(ban_map)} IP (≥{SIG_MIN_HITS}次/类别), 新封 {len(new_ips)}:")
    for ip in sorted(ban_map, key=lambda x: max(ban_map[x].values()), reverse=True)[:15]:
        rl = ",".join(f"{c}×{n}" for c, n in sorted(ban_map[ip].items()))
        log(f"   {'🆕' if ip in new_ips else '✅'} {ip} — {rl}")
    if len(ban_map) > 15: log(f"   ...+{len(ban_map)-15}")

    ad = _ban_new_ips(new_ips, pi, {}, buf, log)
    log(f"\n📊 IPS 新增 {len(ad)} IP")
    fi, _ = len(get_perma_ban_ips()), len(get_perma_ban_subnets())
    log(f"🔢 PERMA-BAN: {fi} IP")
    save_history({"date": now.strftime("%Y-%m-%d"), "time": ns, "new_ips": len(ad), "new_subnets": 0, "total_ips": fi, "mode": "ips", "sig_ips": len(ban_map)})
    return "\n".join(buf)

def do_analyze():
    now = datetime.now(UTC+8); buf = []
    def log(s=""): print(s); buf.append(s)
    log(f"{'='*60}\n  IP 分析 — {now.strftime('%Y-%m-%d %H:%M:%S')} UTC+8\n{'='*60}")
    out = run(["iptables","-L","PERMA-BAN","-n","--line-numbers"])
    rules = []
    for l in out.splitlines():
        l = l.strip()
        if not l or not l[0].isdigit(): continue
        p = l.split()
        if len(p) < 6 or p[1] != "DROP": continue
        m = re.search(r'/\*\s*(.*?)\s*\*/', l); c = m.group(1).strip() if m else ""
        rules.append((int(p[0]), p[4], c))
    log(f"\n📡 规则: {len(rules)}")
    if not rules:
        log("  PERMA-BAN 为空")
        return "\n".join(buf)
    grp = {}
    for n, s, c in rules: grp.setdefault(s, []).append((n, c))
    dups = {s: e for s, e in grp.items() if len(e) > 1}
    if dups: log(f"\n🔍 重复: {len(dups)} 组, {sum(len(e)-1 for e in dups.values())} 可删")
    else: log("\n🔍 无重复 ✅")
    aip = [s for _,s,_ in rules if "/" not in s]; sn = [s for _,s,_ in rules if "/" in s]; uip = list(set(aip))
    log(f"\n🌐 IP: {len(aip)}/{len(uip)} 唯一 | 子网: {len(sn)}")
    log(f"\n📍 GeoIP ({len(uip)}, 缓存)..."); geo = geo_lookup(uip); log(f"   成功 {len(geo)}")
    if geo:
        cc = Counter(v["countryCode"] for v in geo.values()); ac = Counter(v["as"] for v in geo.values())
        log("\n📊 国家 Top 10:"); tl = len(geo)
        for cc2, cnt in cc.most_common(10):
            log(f"   {cc2:6s} {cnt:5d} ({cnt/tl*100:5.1f}%) {'█'*max(1,int(cnt/tl*50))}")
        log("\n🏢 ASN Top 5:")
        for a, cnt in ac.most_common(5): log(f"   {a[:45]:45s} {cnt}")
    res = {ip: info for ip, info in geo.items() if is_residential(info)}
    if res: log(f"\n🏠 住宅ISP ({len(res)}):")
    [log(f"   {ip:18s} {res[ip].get('isp','?'):30s} {res[ip].get('countryCode','?')}") for ip in sorted(res)[:10]]
    if len(res) > 10: log(f"   ...+{len(res)-10}")
    bp = []
    for ip in uip:
        info = geo.get(ip, {})
        if is_bulletproof(info):
            p = ip.split("."); bp.append((ip, f"{p[0]}.{p[1]}.{p[2]}.0/24", info.get("as","?")))
    log(f"\n🛡️ Bulletproof: {len(bp)}")
    [log(f"   {ip:18s} → {sn:18s} {asn}") for ip, sn, asn in bp[:5]]
    if len(bp) > 5: log(f"   ...+{len(bp)-5}")
    log(f"\n⏳ 老化 (>{OLD_THRESHOLD_DAYS}d)...")
    aged = []
    for n, s, c in rules:
        m = re.search(r'(\d{4}-\d{2}-\d{2})', c)
        if m and "/" not in s:
            rd = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=UTC+8)
            ad = (now-rd).days
            if ad > OLD_THRESHOLD_DAYS: aged.append((n, s, c, ad, check_ip_still_active(s)))
    if aged:
        inact = [a for a in aged if not a[4]]; act = [a for a in aged if a[4]]
        log(f"   超{OLD_THRESHOLD_DAYS}d: {len(aged)} ({len(act)}活跃已保留)")
        for n, s, c, d, _ in inact[:10]: log(f"   #{n:4d} {s:20s} ({d}d) 🔇")
        if len(inact) > 10: log(f"   ...+{len(inact)-10}")
    else: log("   无老化 ✅")
    hist = load_history()
    if len(hist) >= 2:
        log(f"\n📈 趋势 ({len(hist)}次):")
        [log(f"   {h['date']}: +{h['new_ips']} IP") for h in hist[-5:]]
    log(f"\n{'='*60}\n  总规则: {len(rules)} | IP: {len(aip)} | 子网: {len(sn)}\n  可删: {sum(len(e)-1 for e in dups.values()) if dups else 0} | BP: {len(bp)} | 住宅: {len(res)}\n✅ 完成")
    return "\n".join(buf)

def do_cleanup(dry_run=False):
    """
    自动维护：去重（同源多条规则保留 1 条）+ 老化清理（>30 天且日志无活跃）。
    dry_run=True 只报告不动手（默认 False 执行删除）。
    安全：子网段不去重只提示；老化只删单 IP 且日志确认无活跃；删除前先验证存在。
    """
    now = datetime.now(UTC+8); buf = []
    def log(s=""): print(s); buf.append(s)
    log(f"🧹 PERMA-BAN 自动维护 — {now.strftime('%Y-%m-%d %H:%M:%S')} UTC+8{' (DRY-RUN)' if dry_run else ''}")
    log("=" * 50)
    out = run(["iptables","-L","PERMA-BAN","-n","--line-numbers"])
    rules = []
    for l in out.splitlines():
        l = l.strip()
        if not l or not l[0].isdigit(): continue
        p = l.split()
        if len(p) < 6 or p[1] != "DROP": continue
        m = re.search(r'/\*\s*(.*?)\s*\*/', l); c = m.group(1).strip() if m else ""
        rules.append((int(p[0]), p[4], c))
    if not rules:
        log("  PERMA-BAN 为空"); return "\n".join(buf)

    # ── 1. 去重（同源多条，保留带注释日期最新的一条）──
    grp = {}
    for n, s, c in rules: grp.setdefault(s, []).append((n, c))
    to_del = []  # (行号, 源, 原因)
    for s, entries in grp.items():
        if len(entries) <= 1: continue
        # 保留：有日期注释的最新一条；无日期注释的旧条目优先删
        def key(e):
            m = re.search(r'(\d{4}-\d{2}-\d{2})', e[1])
            return (1 if m else 0, m.group(1) if m else "")
        entries_sorted = sorted(entries, key=key, reverse=True)
        for e in entries_sorted[1:]:
            to_del.append((e[0], s, "重复"))

    # ── 2. 老化（单 IP，>30 天且日志无活跃）──
    for n, s, c in rules:
        if "/" in s: continue
        m = re.search(r'(\d{4}-\d{2}-\d{2})', c)
        if not m: continue
        rd = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=UTC+8)
        ad = (now - rd).days
        if ad > OLD_THRESHOLD_DAYS:
            if not check_ip_still_active(s):
                to_del.append((n, s, f"老化{ad}d"))

    # 去重排序（行号倒序删，避免行号漂移），同号只删一次
    seen = set(); to_del_u = []
    for n, s, why in sorted(to_del, key=lambda x: -x[0]):
        if n in seen: continue
        seen.add(n); to_del_u.append((n, s, why))

    if not to_del_u:
        log("  ✨ 无需清理：无重复、无老化")
    else:
        log(f"\n🔍 待清理 {len(to_del_u)} 条:")
        for n, s, why in to_del_u:
            log(f"   #{n:4d} {s:20s} ({why})")
        if dry_run:
            log(f"\n⚠️ DRY-RUN：不执行删除（加 --apply 才动手）")
        else:
            fail = 0
            for n, s, why in to_del_u:
                r = subprocess.run(["iptables","-D","PERMA-BAN",str(n)], capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    log(f"   ✅ 已删 #{n} {s} ({why})")
                else:
                    fail += 1
                    log(f"   ❌ 失败 #{n} {s}: {r.stderr.strip()[:60]}")
            if fail == 0:
                _,_,rc = run_raw(["netfilter-persistent","save"])
                log(f"💾 保存: {'成功' if rc==0 else '⚠️ 失败'}")
            else:
                log(f"⚠️ {fail} 条删除失败，未保存（避免部分状态入库）")
    fi, fs = len(get_perma_ban_ips()), len(get_perma_ban_subnets())
    log(f"\n🔢 PERMA-BAN 最终: {fi} IP + {fs} 子网段")
    return "\n".join(buf)

def do_report():
    now = datetime.now(UTC+8)
    print(f"📋 PERMA-BAN ({now.strftime('%Y-%m-%d %H:%M')} UTC+8)")
    ip = get_perma_ban_ips(); sn = get_perma_ban_subnets()
    print(f"   IP: {len(ip)} | 子网: {len(sn)} | 总计: {len(ip)+len(sn)}")
    h = load_history()
    if h:
        print(f"\n📈 记录 ({len(h)}次):")
        for e in h[-5:]:
            m = f" [{e.get('mode','')}]" if e.get('mode') else ""
            print(f"   {e['date']}: +{e['new_ips']} IP{m}")

if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else "sync"
    if m == "cleanup":
        do_cleanup(dry_run="--apply" not in sys.argv)
    else:
        {"sync": do_sync, "daily": do_daily, "ips": do_ips, "analyze": do_analyze, "report": do_report}.get(m, do_sync)()
