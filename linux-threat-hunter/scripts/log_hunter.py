#!/usr/bin/env python3
"""
log_hunter.py — 防火墙日志威胁评分器（YAML 配置化版）
用法: python3 log_hunter.py firewall_export.log
      python3 log_hunter.py - < firewall.log

v2 修复: 规则从 knowledge/rules.yaml 读取（编辑即生效），替代原版硬编码 AWK。
        原版规则散落在 awk 脚本里，改 YAML 不生效。

输入格式 (管道分隔):
  timestamp|src_ip|dst_ip|dst_port|bytes_sent|bytes_recv|protocol
列顺序可在 knowledge/rules.yaml 的 columns 段调整。
"""

import os
import re
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(SCRIPT_DIR, "..", "knowledge", "rules.yaml")


def load_rules():
    """加载 rules.yaml。缺失/损坏时回退内置默认规则（不中断狩猎）。"""
    import yaml
    try:
        with open(RULES_FILE) as f:
            data = yaml.safe_load(f) or {}
        cols = data.get("columns", {})
        rules = [r for r in data.get("rules", []) if r.get("enabled", True)]
        return cols, rules
    except Exception as e:
        print(f"⚠  加载 rules.yaml 失败 ({e})，使用内置默认规则", file=sys.stderr)
        return _default_columns(), _default_rules()


def _default_columns():
    return {"time": 1, "src": 2, "dst": 3, "port": 4, "sent": 5, "recv": 6, "proto": 7}


def _default_rules():
    return [
        {"name": "icmp_tunnel", "field": "proto", "match": "ICMP", "bytes_gt": 500, "score": 50, "tag": "TUNNEL"},
        {"name": "dns_tunnel", "field": "proto", "match": "DNS", "recv_gt": 1500, "score": 50, "tag": "TUNNEL"},
        {"name": "off_hour_exfil", "field": "time", "off_hours": "8-20", "sent_gt": 2000, "sent_ratio": 1.5, "score": 30, "tag": "EXFIL"},
        {"name": "c2_keepalive", "field": "port", "exclude_ports": "80,443,53,123,8080", "sent_range": "1000-50000", "recv_range": "1000-50000", "score": 25, "tag": "C2_KEEPALIVE"},
        {"name": "scan_sensitive_port", "field": "port", "ports": "22,3389,445,1433,3306", "score": 20, "tag": "SCAN"},
    ]


def is_private(ip):
    if not ip or "/" in ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a = int(parts[0]); b = int(parts[1])
    except ValueError:
        return True
    if a == 10 or a == 127 or a == 0:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 100 and 64 <= b <= 127:  # CGNAT
        return True
    return False


def parse_hour(ts):
    m = re.search(r'(?:^|[\sT])(\d{1,2}):(\d{2})', ts)
    if m:
        return int(m.group(1))
    return 23  # 无法解析默认非工作时间，从严


def in_range(val, spec):
    """'1000-50000' → 1000 <= val <= 50000"""
    try:
        lo, hi = spec.split("-")
        return int(lo) <= val <= int(hi)
    except Exception:
        return False


def evaluate(rule, hour, proto, port, sent, recv):
    """单规则判定，返回得分+标签 或 0/None"""
    # 端口白名单（备份服务器等）跳过
    if rule.get("exclude_when"):
        if re.search(rule["exclude_when"], f"hour={hour} proto={proto} port={port}"):
            return 0, None

    if rule.get("field") == "proto":
        if rule.get("match") and proto == rule["match"].upper():
            if rule.get("bytes_gt") and (sent > rule["bytes_gt"] or recv > rule["bytes_gt"]):
                return rule["score"], rule.get("tag")
            if rule.get("recv_gt") and recv > rule["recv_gt"]:
                return rule["score"], rule.get("tag")

    elif rule.get("field") == "time":
        if rule.get("off_hours"):
            try:
                ws, we = rule["off_hours"].split("-")
                off = not (int(ws) <= hour < int(we))
            except Exception:
                off = True
            if off and sent > rule.get("sent_gt", 2000) and sent > recv * rule.get("sent_ratio", 1.5):
                return rule["score"], rule.get("tag")

    elif rule.get("field") == "port":
        if rule.get("ports"):
            if str(port) in [p.strip() for p in rule["ports"].split(",")]:
                return rule["score"], rule.get("tag")
        if rule.get("exclude_ports") and str(port) not in [p.strip() for p in rule["exclude_ports"].split(",")]:
            if (not rule.get("sent_range") or in_range(sent, rule["sent_range"])) and \
               (not rule.get("recv_range") or in_range(recv, rule["recv_range"])):
                return rule["score"], rule.get("tag")
    return 0, None


def main():
    if len(sys.argv) < 2:
        print("用法: python3 log_hunter.py <日志文件> 或 python3 log_hunter.py - < log.csv", file=sys.stderr)
        sys.exit(1)

    log_file = sys.argv[1]
    cols, rules = load_rules()

    ci = {k: int(v) - 1 for k, v in cols.items() if v}
    threshold = int(cols.get("score_threshold", 60))
    block_threshold = int(cols.get("block_threshold", 100))

    totals = defaultdict(int)
    sessions = defaultdict(int)
    evidence = defaultdict(set)
    top_dst = {}
    top_port = {}

    if log_file == "-":
        fh = sys.stdin
    else:
        if not os.path.exists(log_file):
            print(f"ERROR: 日志文件 {log_file} 不存在", file=sys.stderr)
            sys.exit(1)
        fh = open(log_file)

    for line in fh:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        try:
            src = parts[ci["src"]].strip()
            dst = parts[ci["dst"]].strip()
        except IndexError:
            continue
        if is_private(dst):
            continue
        try:
            sent = int(float(parts[ci["sent"]]))
            recv = int(float(parts[ci["recv"]]))
        except (ValueError, IndexError):
            continue
        if sent == 0 and recv == 0:
            continue
        port = parts[ci["port"]].strip()
        proto = parts[ci["proto"]].strip().upper()
        hour = parse_hour(parts[ci["time"]])

        score = 0
        tags = []
        for rule in rules:
            s, tag = evaluate(rule, hour, proto, port, sent, recv)
            if s:
                score += s
                if tag:
                    tags.append(tag)

        if score > 0:
            totals[src] += score
            sessions[src] += 1
            evidence[src].update(tags)
            if score > totals.get(src, 0) - score:  # 记录最高分会话目标
                top_dst[src] = dst
                top_port[src] = port

    if log_file != "-":
        fh.close()

    print(f"{'源IP':<18} {'总分':<7} {'会话数':<8} {'目标IP':<15} {'端口':<6} {'证据标签':<20}")
    print("-" * 78)

    found = 0
    for ip in sorted(totals, key=lambda x: -totals[x]):
        if totals[ip] >= threshold:
            found += 1
            action = "⚠立即封禁" if totals[ip] >= block_threshold else "⚡人工复核"
            print(f"{ip:<18} {totals[ip]:<7} {sessions[ip]:<8} {top_dst.get(ip,'?'):<15} {top_port.get(ip,'?'):<6} {' '.join(sorted(evidence[ip])):<20} [{action}]")

    if found == 0:
        print("\nℹ  所有外联行为均在安全阈值以内")

    print("\n###BLOCK_LIST_START###")
    for ip in sorted(totals, key=lambda x: -totals[x]):
        if totals[ip] >= block_threshold:
            print(ip)
    print("###BLOCK_LIST_END###")

    # 摘要到 stderr 供日志查看
    print(f"评分完成: {len(totals)} 个源IP, {found} 个达阈值, {sum(1 for v in totals.values() if v >= block_threshold)} 个需封禁", file=sys.stderr)


if __name__ == "__main__":
    main()
