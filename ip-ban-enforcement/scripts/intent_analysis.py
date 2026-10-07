#!/usr/bin/env python3
"""
intent_analysis.py — 网络威胁意图分析（B 方案：独立画像报告）
对每个攻击 IP 判定意图：🕵️侦察扫描 / 💥暴力破解 / 🎯定向攻击 / 🤖僵尸网络 / 🕷️爬虫CC滥用
输出: 意图分布汇总 + Top 攻击者画像（意图/置信度/证据/处置建议）+ 与上周对比趋势

用法:
  python3 intent_analysis.py            # 全量分析（窗口 7 天）
  python3 intent_analysis.py --top 20   # Top N 画像
  python3 intent_analysis.py --json     # JSON 输出（供 cron/程序消费）
  python3 intent_analysis.py --cron     # 静默模式：有高危定向攻击才详细输出，否则一行摘要
"""

import os, sys, json, argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from intent_lib import (
    RULES, analyze_ip, get_attack_rules_for_ips, intent_category_label,
    intent_action, load_intent_rules, collect_access_behaviors_all,
)

UTC+8 = timezone(timedelta(hours=8))

def intent_display(intent):
    """intent 可能是 'exploit' / 'mixed:recon+brute' / 'mixed'，返回带 emoji 的显示名。"""
    if intent.startswith("mixed"):
        parts = intent.split(":")[1].split("+") if ":" in intent else []
        if parts:
            labels = [intent_category_label(p).split(" ")[1] for p in parts]
            return "🌀 " + "+".join(labels)
        return "🌀 混合意图"
    return intent_category_label(intent)

def intent_base(intent):
    """取意图主类别（mixed 取第一个）。"""
    return intent.split(":")[0]

# 批量统计 fail2ban SSH Found（一次 zgrep 聚合所有 IP）
def collect_ssh_counts_all(target_ips, window_days=None):
    """返回 {ip: (count, distinct_days)} — 单次 zgrep 聚合。"""
    if window_days is None: window_days = RULES["thresholds"]["window_days"]
    target_ips = set(target_ips)
    if not target_ips: return {}
    ef = [f for f in ["/var/log/fail2ban.log","/var/log/fail2ban.log.1",
                      "/var/log/fail2ban.log.2.gz","/var/log/fail2ban.log.3.gz"] if os.path.exists(f)]
    if not ef: return {ip: (0, 0) for ip in target_ips}
    acc = {ip: (0, set()) for ip in target_ips}
    try:
        r = subprocess.run(["zgrep","-h",r"\[sshd\].*Found",*ef], capture_output=True, text=True, timeout=60)
        for l in r.stdout.splitlines():
            m = re.match(r"(\d{4}-\d{2}-\d{2}).*Found (\d+\.\d+\.\d+\.\d+)", l)
            if not m: continue
            ip = m.group(2)
            if ip in acc:
                cnt, days = acc[ip]
                acc[ip] = (cnt + 1, days | {m.group(1)})
    except: pass
    return {ip: (c, len(d)) for ip, (c, d) in acc.items()}

# ─── 趋势对比（上周同期） ───────────────────────────
def load_trend_history():
    fp = os.path.expanduser("~/.hermes/cache/intent_history.json")
    if os.path.exists(fp):
        try:
            import json as _j
            return _j.load(open(fp))
        except: pass
    return []

def save_trend_history(entry):
    import json as _j
    os.makedirs(os.path.expanduser("~/.hermes/cache"), exist_ok=True)
    h = load_trend_history()
    h.append(entry)
    h = h[-52:]
    fp = os.path.expanduser("~/.hermes/cache/intent_history.json")
    tmp = fp + ".tmp"
    _j.dump(h, open(tmp, "w"), indent=2)
    os.replace(tmp, fp)

# ─── 报告生成 ───────────────────────────────────────
def analyze_all(window_days=None, top_n=None):
    if window_days is None: window_days = RULES["thresholds"]["window_days"]
    if top_n is None: top_n = RULES["thresholds"]["top_n"]
    window_hours = window_days * 24

    rule_map = get_attack_rules_for_ips(window_hours)
    if not rule_map:
        return {"window_days": window_days, "ips": [], "intent_dist": {}, "error": "无攻击日志（或数据库不可读）"}

    # 批量采集：access.log 一次遍历 + SSH 一次 zgrep
    ip_list = list(rule_map.keys())
    access_beh = collect_access_behaviors_all(ip_list, window_days=window_days)
    ssh_counts = collect_ssh_counts_all(ip_list, window_days=window_days)

    results = []
    for ip in ip_list:
        ab = access_beh.get(ip, {})
        behaviors = {}
        behaviors.update({k: v for k, v in ab.items() if k != "narrow_uri"})
        behaviors["narrow_uri"] = ab.get("narrow_uri")
        behaviors["narrow_cnt"] = ab.get("narrow_cnt", 0)
        ssh_cnt, ssh_days = ssh_counts.get(ip, (0, 0))
        behaviors["ssh_cnt"], behaviors["ssh_days"] = ssh_cnt, ssh_days
        r = analyze_ip(ip, window_hours=window_hours, behaviors=behaviors)
        results.append(r)

    # 排序：定向攻击 > 爆破 > 僵尸 > 扫描 > 滥用，再按置信度
    pri = RULES["disposition_priority"]
    def sort_key(r):
        base = r["intent"].split(":")[0]  # mixed:x+y 取第一个
        return (pri.get(base, 0), r.get("confidence", 0), r.get("total", 0))
    results.sort(key=sort_key, reverse=True)

    dist = Counter()
    for r in results:
        base = intent_base(r["intent"])
        dist[base] += 1

    return {"window_days": window_days, "ips": results, "intent_dist": dict(dist), "top_n": top_n}

def format_report(data, top_n=None):
    """生成人类可读报告。"""
    if top_n is None: top_n = data.get("top_n", 15)
    now = datetime.now(UTC+8)
    lines = []
    lines.append(f"🎯 网络威胁意图分析 — {now.strftime('%Y-%m-%d %H:%M')} UTC+8 (窗口 {data['window_days']}d)")
    lines.append("=" * 58)
    if data.get("error"):
        lines.append(f"⚠️ {data['error']}")
        return "\n".join(lines)

    dist = data["intent_dist"]
    total = len(data["ips"])
    lines.append(f"\n📊 意图分布 (共 {total} 个攻击 IP):")
    pri = RULES["disposition_priority"]
    for intent in sorted(dist, key=lambda x: pri.get(x, 0), reverse=True):
        cnt = dist[intent]
        label = intent_display(intent)
        pct = cnt / total * 100
        bar = "█" * max(1, int(pct / 100 * 30))
        lines.append(f"   {label:12s} {cnt:4d} ({pct:5.1f}%) {bar}")

    # 高危意图（定向/爆破）Top
    high_risk = [r for r in data["ips"] if intent_base(r["intent"]) in ("exploit", "brute")]
    if high_risk:
        lines.append(f"\n🚨 高危意图 (定向/爆破, {len(high_risk)}):")
        for r in high_risk[:10]:
            label = intent_display(r["intent"])
            feats = ", ".join(r["features"][:3])
            lines.append(f"   {label} {r['ip']} — 置信{int(r['confidence']*100)}% [{feats}]")

    # Top N 画像
    lines.append(f"\n📋 攻击者画像 Top {min(top_n, len(data['ips']))}:")
    lines.append(f"   {'意图':10s} {'IP':18s} {'置信':6s} {'证据特征'}")
    lines.append("   " + "-" * 52)
    for r in data["ips"][:top_n]:
        base = intent_base(r["intent"])
        label = intent_display(r["intent"])
        feats = ", ".join(r["features"][:3]) if r["features"] else f"规则{r.get('rules', {})}"
        conf = f"{int(r['confidence']*100)}%"
        lines.append(f"   {label:10s} {r['ip']:18s} {conf:6s} {feats[:36]}")
        action = intent_action(base)
        if action and base in ("exploit", "brute"):
            lines.append(f"            └─ 建议: {action}")

    return "\n".join(lines)

def run_cron_mode():
    """cron 静默模式：无高危定向攻击 → 一行摘要；有 → 详细输出。"""
    data = analyze_all()
    if data.get("error"):
        print(f"⚠️ {data['error']}")
        return
    dist = data["intent_dist"]
    exploit_n = dist.get("exploit", 0)
    brute_n = dist.get("brute", 0)
    total = len(data["ips"])
    if exploit_n > 0:
        # 有定向攻击 → 详细报告
        print(format_report(data))
    else:
        lines = [f"🎯 意图分析 ({data['window_days']}d): 共{total} IP"]
        for intent in ("exploit", "brute", "botnet", "recon", "abuse"):
            if dist.get(intent):
                lines.append(f"{intent_category_label(intent).split(' ')[1]}{dist[intent]}")
        print(" | ".join(lines))

def main():
    ap = argparse.ArgumentParser(description="网络威胁意图分析")
    ap.add_argument("--top", type=int, default=None, help="Top N 画像数")
    ap.add_argument("--days", type=int, default=None, help="分析窗口天数")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--cron", action="store_true", help="cron 静默模式")
    ap.add_argument("--save", action="store_true", help="保存趋势历史")
    args = ap.parse_args()

    if args.cron:
        # cron 模式也要保存趋势（--cron --save 组合是 cron job 的标准用法）
        if args.save:
            data = analyze_all()
            if not data.get("error"):
                now = datetime.now(UTC+8).strftime("%Y-%m-%d")
                save_trend_history({"date": now, **data["intent_dist"]})
        run_cron_mode()
        return

    data = analyze_all(window_days=args.days, top_n=args.top)

    if args.save:
        now = datetime.now(UTC+8).strftime("%Y-%m-%d")
        save_trend_history({"date": now, **data["intent_dist"]})

    if args.json:
        print(json.dumps(data, ensure_ascii=False, default=str, indent=2))
    else:
        print(format_report(data, top_n=args.top))
        # 历史趋势
        hist = load_trend_history()
        if len(hist) >= 2:
            p = hist[-2]
            print(f"\n📈 趋势 (vs {p.get('date','上周')}):")
            for k in ("exploit", "brute"):
                cur = data["intent_dist"].get(k, 0)
                prev = p.get(k, 0)
                if cur or prev:
                    arrow = "🔴" if cur > prev else ("🟢" if cur < prev else "➡️")
                    print(f"   {intent_category_label(k).split(' ')[1]}: {prev} → {cur} {arrow}")

if __name__ == "__main__":
    main()
