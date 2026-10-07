#!/usr/bin/env python3
"""
learn.py — 威胁狩猎案例学习入库 + 查询匹配
用法:
  入库: python3 learn.py "<狩猎报告>" 或 cat report.txt | python3 learn.py
  查询: python3 learn.py --query "ICMP TUNNEL 1.2.3.4"   # 狩猎时匹配历史案例
  列出: python3 learn.py --list

v2 修复: 原版只能存报告原文（半成品）。新增 --query 匹配逻辑：
  按 IP、证据标签、高分段三重匹配，命中返回历史案例与处置建议，
  供狩猎时直接参考（SKILL.md 声明的"下次优先匹配"现在真正生效）。
"""

import json
import os
import re
import sys
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CASES_FILE = os.path.join(SCRIPT_DIR, "..", "references", "cases.db.json")

TAGS = ["TUNNEL", "EXFIL", "C2_KEEPALIVE", "SCAN"]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_cases():
    try:
        with open(CASES_FILE) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_cases(cases):
    os.makedirs(os.path.dirname(CASES_FILE), exist_ok=True)
    with open(CASES_FILE, "w") as f:
        json.dump(cases, f, ensure_ascii=False, indent=2)


def extract_key_info(report_text):
    """从狩猎报告中提取关键信息"""
    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "original": report_text[:500],
    }
    info["ips_involved"] = list(set(IP_RE.findall(report_text))) or []
    score_match = re.search(r"总分[：:]\s*(\d+)", report_text)
    if not score_match:
        score_match = re.search(r"\|\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*\|\s*(\d+)", report_text)
    info["max_score"] = int(score_match.group(1)) if score_match else 0
    info["evidence_tags"] = list(set(t for t in TAGS if t in report_text))
    info["blocked"] = "已自动封禁" in report_text or "封禁" in report_text
    return info


def match_cases(cases, text):
    """按 3 重信号匹配历史案例，返回 (案例列表, 最高分)"""
    text_ips = set(IP_RE.findall(text))
    text_tags = set(t for t in TAGS if t in text)
    text_score = 0
    m = re.search(r"总分[：:]\s*(\d+)", text)
    if m:
        text_score = int(m.group(1))

    hits = []
    for c in cases:
        score = 0
        reasons = []
        # 1. IP 重叠
        ip_overlap = text_ips & set(c.get("ips_involved", []))
        if ip_overlap:
            score += 40
            reasons.append(f"IP命中 {','.join(sorted(ip_overlap))}")
        # 2. 证据标签重叠
        tag_overlap = text_tags & set(c.get("evidence_tags", []))
        if tag_overlap:
            score += 30
            reasons.append(f"标签 {'+'.join(sorted(tag_overlap))}")
        # 3. 高分段接近（±20 分）
        if c.get("max_score") and abs(c.get("max_score", 0) - text_score) <= 20 and text_score > 0:
            score += 20
            reasons.append(f"分数接近 {c.get('max_score')}")
        # 4. 历史命中次数加权
        score += min(c.get("hit_count", 1) - 1, 3) * 5

        if score >= 30:
            hits.append((score, c, reasons))

    hits.sort(key=lambda x: -x[0])
    return hits, text_score


def do_query(text):
    cases = load_cases()
    if not cases:
        print("ℹ  案例库为空 — 狩猎后可执行 learn.py 入库建立记忆")
        return
    hits, text_score = match_cases(cases, text)
    if not hits:
        print(f"ℹ  未命中历史案例 (案例库 {len(cases)} 个)")
        return
    print(f"📚 命中 {len(hits)} 个历史案例 (案例库 {len(cases)} 个):")
    for score, c, reasons in hits[:5]:
        print(f"  ── 匹配度 {score}%")
        print(f"     时间: {c.get('timestamp','?')} | 命中 {c.get('hit_count',1)} 次")
        print(f"     证据: {', '.join(c.get('evidence_tags',[])) or '?'} | 分数: {c.get('max_score','?')}")
        if c.get("ips_involved"):
            print(f"     IP: {', '.join(c['ips_involved'][:5])}")
        if c.get("original"):
            print(f"     原文: {c['original'][:120]}")
        print(f"     参考: {'已封禁' if c.get('blocked') else '人工复核'} | 建议: {reasons[0] if reasons else ''}")


def do_list():
    cases = load_cases()
    if not cases:
        print("ℹ  案例库为空")
        return
    print(f"📚 案例库共 {len(cases)} 个:")
    for i, c in enumerate(cases, 1):
        print(f"  {i}. [{c.get('timestamp','?')}] 命中{c.get('hit_count',1)}次 分{c.get('max_score','?')} "
              f"标签{','.join(c.get('evidence_tags',[])) or '?'} IP:{','.join(c.get('ips_involved',[])[:3])}")


def main():
    args = sys.argv[1:]

    if args and args[0] == "--list":
        do_list()
        return
    if args and args[0] == "--query":
        if len(args) < 2:
            print("用法: python3 learn.py --query \"<线索描述/IP/标签>\"", file=sys.stderr)
            sys.exit(1)
        do_query(args[1])
        return

    # 入库模式：优先命令行参数（非 TTY 环境 stdin 可能为空），否则读 stdin
    if args:
        report = args[0]
    elif not sys.stdin.isatty():
        report = sys.stdin.read().strip()
    else:
        print("用法: python3 learn.py \"<狩猎报告>\" | cat report.txt | python3 learn.py | --query \"<线索>\" | --list", file=sys.stderr)
        sys.exit(1)

    case = extract_key_info(report)
    cases = load_cases()

    # 去重：相同 IP 组合 + 相同标签 → 更新计数
    for existing in cases:
        if (set(existing.get("ips_involved", [])) == set(case["ips_involved"])
                and set(existing.get("evidence_tags", [])) == set(case["evidence_tags"])):
            existing["last_seen"] = case["timestamp"]
            existing["hit_count"] = existing.get("hit_count", 1) + 1
            save_cases(cases)
            print(f"✅ 案例已更新 (命中次数: {existing['hit_count']})")
            return

    case["hit_count"] = 1
    case["last_seen"] = case["timestamp"]
    cases.append(case)
    save_cases(cases)
    print(f"✅ 新案例已保存 (共 {len(cases)} 个案例)")


if __name__ == "__main__":
    main()
