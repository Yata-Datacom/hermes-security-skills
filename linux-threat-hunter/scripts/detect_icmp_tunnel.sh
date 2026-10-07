#!/bin/bash
# detect_icmp_tunnel.sh — ICMP 大包检测隧道行为（多后端降级）
# 用法:
#   实时抓取: ./detect_icmp_tunnel.sh [网卡] [持续秒数]
#   离线分析: ./detect_icmp_tunnel.sh -r /path/to/pcap
# 示例: ./detect_icmp_tunnel.sh eth0 60
#       ./detect_icmp_tunnel.sh -r /tmp/capture.pcap
#
# 阈值: ICMP 载荷 > 128 字节 (正常 ping 最大 64 字节)
# 后端优先级: tshark → tcpdump（无 tshark 时自动降级，无需 Wireshark 全家桶）
#   - tshark:  过滤 data.len > 128 直接取载荷字节
#   - tcpdump: IP 总长 > 156 (=128 载荷 + 20 IP头 + 8 ICMP头) 判异常

MODE="live"
INTERFACE="${1:-eth0}"
DURATION="${2:-60}"
TMPFILE="/tmp/icmp_hunt_$$.csv"
THRESHOLD=128          # ICMP 载荷阈值
TCPDUMP_LEN_THRESHOLD=156  # IP 总长阈值 = 128 + 20 + 8

if [ "$1" = "-r" ]; then
  MODE="pcap"
  PCAP_FILE="$2"
  if [ ! -f "$PCAP_FILE" ]; then
    echo "ERROR: PCAP 文件 $PCAP_FILE 不存在" >&2
    exit 1
  fi
fi

# ── 后端选择 ──
if command -v tshark >/dev/null 2>&1; then
  BACKEND="tshark"
elif command -v tcpdump >/dev/null 2>&1; then
  BACKEND="tcpdump"
else
  echo "ERROR: 需要 tshark 或 tcpdump (apt-get install tshark 或 tcpdump)" >&2
  exit 1
fi

echo "ℹ  后端: $BACKEND (ICMP 载荷 > ${THRESHOLD}B 判隧道)" >&2

if [ "$BACKEND" = "tshark" ]; then
  # ── tshark 路径：直接过滤 data.len ──
  if [ "$MODE" = "live" ]; then
    tshark -i "$INTERFACE" -a duration:"$DURATION" \
      -Y "icmp and data.len > $THRESHOLD and icmp.type != 3" \
      -T fields -e frame.time -e ip.src -e ip.dst -e data.len \
      -E header=y -E separator=',' 2>/dev/null > "$TMPFILE"
    CAPTURE_SOURCE="网卡 $INTERFACE (${DURATION}s)"
  else
    tshark -r "$PCAP_FILE" \
      -Y "icmp and data.len > $THRESHOLD and icmp.type != 3" \
      -T fields -e frame.time -e ip.src -e ip.dst -e data.len \
      -E header=y -E separator=',' 2>/dev/null > "$TMPFILE"
    CAPTURE_SOURCE="PCAP $(basename "$PCAP_FILE")"
  fi
else
  # ── tcpdump 路径：IP 总长 > 156 (载荷>128) ──
  if [ "$MODE" = "live" ]; then
    timeout "$DURATION" tcpdump -i "$INTERFACE" -nn -l 'icmp' 2>/dev/null > "$TMPFILE"
    CAPTURE_SOURCE="网卡 $INTERFACE (${DURATION}s)"
  else
    tcpdump -r "$PCAP_FILE" -nn 'icmp' 2>/dev/null > "$TMPFILE"
    CAPTURE_SOURCE="PCAP $(basename "$PCAP_FILE")"
  fi
  # 解析: 行尾 length N → 提取 >156 的行，转成 CSV
  awk -v thr="$TCPDUMP_LEN_THRESHOLD" '
    /length [0-9]+/ {
      n = $0; sub(/.*length /, "", n); n += 0
      if (n > thr) {
        # 时间 源 > 目标:  ...
        match($0, /^[0-9:.]+/); t = substr($0, RSTART, RLENGTH)
        # 提取源和目标 IP (跳过端口)
        ips = ""
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
            gsub(/:/, "", $i)
            ips = ips $i ","
            if (++c == 2) break
          }
        }
        # 载荷 = IP总长 - 20 - 8
        payload = n - 28
        printf "%s,%s%s\n", t, ips, payload
      }
    }' "$TMPFILE" > "${TMPFILE}.parsed"
  mv "${TMPFILE}.parsed" "$TMPFILE"
fi

COUNT=$(tail -n +2 "$TMPFILE" 2>/dev/null | wc -l)

if [ "$COUNT" -gt 0 ]; then
  echo "=========================================="
  echo "⚠  发现 $COUNT 个疑似 ICMP 隧道会话 ($CAPTURE_SOURCE)"
  echo "=========================================="
  echo "时间戳            源IP            目标IP          载荷字节"
  awk -F',' 'NR>1 && $4>0 {printf "%-18s %-15s %-15s %s\n", $1, $2, $3, $4}' "$TMPFILE"
else
  echo "✅ 未检测到 ICMP 隧道行为 ($CAPTURE_SOURCE)"
fi

echo "TUNNEL_COUNT=$COUNT" >&2
rm -f "$TMPFILE"
exit 0
