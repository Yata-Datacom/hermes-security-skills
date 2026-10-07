#!/bin/bash
# detect_dns_tunnel.sh — 分析 PCAP 中的 DNS 大响应（隧道特征，多后端降级）
# 用法: ./detect_dns_tunnel.sh /path/to/capture.pcap
# 阈值：DNS 响应 > 1500 字节（兼容 EDNS0，大幅降低误报）
#
# 后端优先级: tshark → tcpdump（无 tshark 时自动降级）
#   - tshark:  过滤 dns.resp.len > 1500 直接取响应长度
#   - tcpdump: 识别 ".53 > " 方向（响应）+ IP 总长 > 1528 (=1500+20+8)

PCAP_FILE="$1"

if [ ! -f "$PCAP_FILE" ]; then
  echo "ERROR: PCAP 文件 $PCAP_FILE 不存在" >&2
  exit 1
fi

if command -v tshark >/dev/null 2>&1; then
  BACKEND="tshark"
elif command -v tcpdump >/dev/null 2>&1; then
  BACKEND="tcpdump"
else
  echo "ERROR: 需要 tshark 或 tcpdump" >&2
  exit 1
fi

echo "ℹ  后端: $BACKEND (DNS 响应 > 1500B 判隧道)" >&2
TMPFILE="/tmp/dns_hunt_$$.csv"
DNS_THRESHOLD=1500
TCPDUMP_LEN_THRESHOLD=1528  # 1500 + 20 IP头 + 8 UDP头

if [ "$BACKEND" = "tshark" ]; then
  tshark -r "$PCAP_FILE" \
    -Y "dns and udp.dstport == 53 and dns.resp.len > $DNS_THRESHOLD" \
    -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.resp.len \
    -E header=y -E separator=',' 2>/dev/null > "$TMPFILE"
else
  # tcpdump 路径：只看 DNS 响应方向 (sport 53)，IP 总长 > 1528
  tcpdump -r "$PCAP_FILE" -nn 'udp port 53 and greater 1528' 2>/dev/null > "$TMPFILE"
  awk '
    /\.53 > .*length [0-9]+/ {
      # 仅响应方向：sport 53（"x.x.x.x.53 >"）
      if ($0 ~ /\.53 >/) {
        n = $0; sub(/.*length /, "", n); n += 0
        match($0, /^[0-9:.]+/); t = substr($0, RSTART, RLENGTH)
        # 源(响应方) 目标(查询方)
        src = ""; dst = ""; c = 0
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
            gsub(/:/, "", $i); gsub(/\.[0-9]+$/, "", $i)
            if (c == 0) src = $i; else if (c == 1) dst = $i
            c++
            if (c == 2) break
          }
        }
        resp = n - 28  # 减 IP头+UDP头
        # 查询名从后续行不易取，置空
        printf "%s,%s,%s,,%s\n", t, src, dst, resp
      }
    }' "$TMPFILE" > "${TMPFILE}.parsed"
  mv "${TMPFILE}.parsed" "$TMPFILE"
fi

COUNT=$(tail -n +2 "$TMPFILE" 2>/dev/null | wc -l)

if [ "$COUNT" -gt 0 ]; then
  echo "=========================================="
  echo "⚠  发现 $COUNT 个疑似 DNS 隧道请求 (响应 > ${DNS_THRESHOLD} 字节)"
  echo "=========================================="
  echo "时间戳            源IP            DNS服务器       查询域名                        响应字节"
  awk -F',' 'NR>1 && $5>'"$DNS_THRESHOLD"' {printf "%-18s %-15s %-15s %-30s %s\n", $1, $2, $3, $4, $5}' "$TMPFILE"

  echo ""
  echo "--- 高价值线索: 高频顶级域名 ---"
  awk -F',' 'NR>1 {
    split($4, parts, ".");
    if (length(parts) >= 2) {
      tld = parts[length(parts)-1] "." parts[length(parts)];
      top[tld]++
    }
  } END {
    for(t in top) print top[t], t | "sort -rn | head -5"
  }' "$TMPFILE"

  echo ""
  echo "--- 按源 IP 统计可疑 DNS 请求数 ---"
  awk -F',' 'NR>1 {src[$2]++} END {for(s in src) print src[s], s | "sort -rn"}' "$TMPFILE"
else
  echo "✅ 未检测到 DNS 隧道行为 (阈值: >${DNS_THRESHOLD} 字节)"
fi

echo "TUNNEL_COUNT=$COUNT" >&2
rm -f "$TMPFILE"
exit 0
