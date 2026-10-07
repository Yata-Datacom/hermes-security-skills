#!/usr/bin/env python3
"""
detect_dga.py — DGA（域名生成算法）随机域名检测
用法: python3 detect_dga.py /path/to/capture.pcap
      python3 detect_dga.py - < dns_queries.txt   # 从 stdin 读纯域名列表

原理: DGA 生成的域名（僵尸网络/恶意软件回连）子域为随机字符串:
  - 字符熵高（字符分布均匀，不像英文单词有规律）
  - 元音比例低（< 0.18，英文单词通常 > 0.3）
  - 数字密度高（随机串常混入数字）
  - 子域较长（≥ 8 字符）

评分: 熵>3.5 +30, 元音比<0.18 +30, 数字比>0.2 +20, 长度≥10 +20 → ≥50 判疑似 DGA

后端: tshark（dns.qry.name 字段）→ tcpdump（-vv 输出 A? 记录）→ 无 pcap 时读 stdin
"""

import json
import math
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

ENTROPY_THRESHOLD = 3.5
VOWEL_RATIO_MAX = 0.18
DIGIT_RATIO_MIN = 0.20
LENGTH_MIN = 10
SCORE_THRESHOLD = 50


def shannon_entropy(s):
    """字符串香农熵（bits/char）"""
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def dga_score(sub):
    """对单个子域打 DGA 分数，返回 (score, 特征dict)"""
    if len(sub) < 6:
        return 0, {}
    ent = shannon_entropy(sub)
    vowels = sum(1 for ch in sub if ch.lower() in "aeiou")
    vowel_ratio = vowels / len(sub)
    digits = sum(1 for ch in sub if ch.isdigit())
    digit_ratio = digits / len(sub)

    score = 0
    feats = {
        "entropy": round(ent, 2),
        "vowel_ratio": round(vowel_ratio, 2),
        "digit_ratio": round(digit_ratio, 2),
        "len": len(sub),
    }
    if ent > ENTROPY_THRESHOLD:
        score += 30
    if vowel_ratio < VOWEL_RATIO_MAX:
        score += 30
    if digit_ratio > DIGIT_RATIO_MIN:
        score += 20
    if len(sub) >= LENGTH_MIN:
        score += 20
    return score, feats


def extract_from_pcap(pcap):
    """tshark → tcpdump 提取 DNS 查询域名列表"""
    if not os.path.exists(pcap):
        print(f"ERROR: PCAP 文件 {pcap} 不存在", file=sys.stderr)
        sys.exit(1)

    # 后端 1: tshark
    if subprocess.run(["sh", "-c", "command -v tshark"], capture_output=True).returncode == 0:
        try:
            out = subprocess.run(
                ["tshark", "-r", pcap, "-Y", "dns.qry.name",
                 "-T", "fields", "-e", "dns.qry.name", "-E", "header=n"],
                capture_output=True, text=True, timeout=60,
            ).stdout
            domains = [ln.strip().rstrip(".") for ln in out.splitlines() if ln.strip() and "." in ln]
            if domains:
                return domains, "tshark"
        except Exception:
            pass

    # 后端 2: tcpdump -vv（输出 "A? example.com. (30)" 或 "1.2.3.4.53 > ...  A? example.com."）
    out = subprocess.run(
        ["tcpdump", "-r", pcap, "-vv", "-nn", "udp port 53"],
        capture_output=True, text=True, timeout=60,
    ).stdout
    domains = []
    for m in re.finditer(r"\b[A-Za-z]\??\s+([A-Za-z0-9][A-Za-z0-9._-]+)\.\s*\(", out):
        d = m.group(1).rstrip(".")
        if "." in d and not d.endswith("in-addr"):
            domains.append(d)
    if not domains:
        # 兜底: 抓任意 "A? xxx" / "AAAA? xxx" 模式
        for m in re.finditer(r"\b(?:A|AAAA|CNAME|TXT|MX)\?\s+([A-Za-z0-9][A-Za-z0-9._-]+)\.", out):
            d = m.group(1).rstrip(".")
            if "." in d:
                domains.append(d)
    return list(dict.fromkeys(domains)), "tcpdump"


def main():
    if len(sys.argv) < 2:
        print("用法: python3 detect_dga.py /path/to/capture.pcap 或 python3 detect_dga.py - < domains.txt", file=sys.stderr)
        sys.exit(1)

    pcap = sys.argv[1]
    if pcap == "-":
        domains = [ln.strip().rstrip(".") for ln in sys.stdin if ln.strip() and "." in ln]
        backend = "stdin"
    else:
        domains, backend = extract_from_pcap(pcap)

    print(f"ℹ  后端: {backend} | 提取 {len(domains)} 个 DNS 查询域名" , file=sys.stderr)

    # 按子域聚合计数
    sub_counter = defaultdict(int)
    sub_domain_map = {}
    for d in domains:
        labels = d.split(".")
        if len(labels) < 2:
            continue
        sub = labels[0]  # 最左子域（DGA 随机部分通常在这）
        if not sub or not re.match(r"^[a-z0-9]+$", sub, re.I):
            continue
        sub_counter[sub] += 1
        sub_domain_map.setdefault(sub, d)

    hits = []
    for sub, cnt in sub_counter.items():
        score, feats = dga_score(sub)
        if score >= SCORE_THRESHOLD:
            hits.append((score, sub, cnt, feats, sub_domain_map[sub]))

    hits.sort(key=lambda x: -x[0])

    if hits:
        print("==========================================")
        print(f"⚠  发现 {len(hits)} 个疑似 DGA 随机域名 (评分 ≥ {SCORE_THRESHOLD})")
        print("==========================================")
        print(f"{'评分':<6} {'子域':<28} {'查询数':<7} {'熵':<6} {'元音比':<7} {'数字比':<7} 完整域名")
        for score, sub, cnt, feats, full in hits[:20]:
            print(f"{score:<6} {sub:<28} {cnt:<7} {feats['entropy']:<6} {feats['vowel_ratio']:<7} {feats['digit_ratio']:<7} {full}")
        print("")
        print("💡 处置建议: 高熵+低元音子域通常为 DGA，确认后对目标 IP 封堵，")
        print("   并排查本机是否有恶意进程在解析这些域名 (ss -tnp / lsof -i)")
    else:
        print(f"✅ 未检测到疑似 DGA 域名 (阈值: 熵>{ENTROPY_THRESHOLD}, 元音比<{VOWEL_RATIO_MAX}, 评分≥{SCORE_THRESHOLD})")

    print(f"DGA_COUNT={len(hits)}", file=sys.stderr)


if __name__ == "__main__":
    main()
