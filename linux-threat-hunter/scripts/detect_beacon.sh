#!/bin/bash
# detect_beacon.sh — C2 Beacon 心跳周期检测（多后端降级）
# 用法: ./detect_beacon.sh /path/to/capture.pcap [最小样本数]
# 示例: ./detect_beacon.sh /tmp/capture.pcap 5
#
# 原理: C2 僵尸主机的命令心跳（beacon）间隔高度规律。
#   对每个 (源IP→目标IP:端口) 连接对，统计时间戳间隔的变异系数 CV = σ/μ。
#   CV < 0.25 且样本 ≥ 5 → 规律心跳，疑似 C2 通信。
#   与 log_hunter 的 C2_KEEPALIVE（只看流量均衡）互补：本脚本看时间规律。
#
# 后端优先级: tshark → tcpdump（无 tshark 自动降级）

PCAP_FILE="$1"
MIN_SAMPLES="${2:-5}"
CV_THRESHOLD=0.25
TMPFILE="/tmp/beacon_hunt_$$.csv"

if [ -z "$PCAP_FILE" ]; then
  echo "ERROR: 用法 $0 /path/to/capture.pcap [最小样本数]" >&2
  exit 1
fi
if [ ! -f "$PCAP_FILE" ]; then
  echo "ERROR: PCAP 文件 $PCAP_FILE 不存在" >&2
  exit 1
fi

if command -v tshark >/dev/null 2>&1; then
  BACKEND="tshark"
  echo "ℹ  后端: tshark (beacon: 间隔CV<$CV_THRESHOLD, 样本≥$MIN_SAMPLES)" >&2
  # 提取 TCP 会话时间戳: epoch,src,dst,port
  tshark -r "$PCAP_FILE" -Y "tcp" \
    -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport \
    -E header=n -E separator=',' 2>/dev/null | \
    awk -F',' 'NF==4 && $1!="" {printf "%s,%s,%s,%s\n", $2, $3, $4, $1}' | \
    sort -t',' -k1,1 -k2,2 -k3,3 -k4,4n > "$TMPFILE"
else
  BACKEND="tcpdump"
  echo "ℹ  后端: tcpdump (beacon: 间隔CV<$CV_THRESHOLD, 样本≥$MIN_SAMPLES)" >&2
  # tcpdump epoch 输出: "1234567890.123456 IP 1.2.3.4.56789 > 8.8.8.8.443: ..."
  tcpdump -r "$PCAP_FILE" -tt -nn 'tcp' 2>/dev/null | \
    awk '{
      time = $1
      srcfull = $3; sub(/:/, "", srcfull)
      dstfull = $5; sub(/:/, "", dstfull)
      n = split(srcfull, sa, "."); src = sa[1]"."sa[2]"."sa[3]"."sa[4]; sport = sa[n]
      n = split(dstfull, da, "."); dst = da[1]"."da[2]"."da[3]"."da[4]; dport = da[n]
      printf "%s,%s,%s,%s\n", src, dst, dport, time
    }' | \
    sort -t',' -k1,1 -k2,2 -k3,3 -k4,4n > "$TMPFILE"
fi

# ── 分组统计：每组时间戳间隔的均值/标准差/CV ──
awk -F',' -v cv_thr="$CV_THRESHOLD" -v min_n="$MIN_SAMPLES" '
{
  key = $1 "," $2 "," $3
  if (key != last_key && last_key != "") { emit(); reset() }
  if (key != last_key) { last_key = key; src=$1; dst=$2; port=$3; n=0; sum=0; sumsq=0; prev=-1 }
  t = $4 + 0
  if (prev >= 0) { d = t - prev; n++; sum += d; sumsq += d*d }
  prev = t
}
END { if (last_key != "") emit() }

function emit() {
  if (n >= min_n) {
    mean = sum / n
    if (mean > 0) {
      var = (sumsq / n) - (mean * mean)
      if (var < 0) var = 0
      std = sqrt(var)
      cv = std / mean
      if (cv < cv_thr) {
        printf "%s,%s,%s,%d,%.1f,%.3f\n", src, dst, port, n, mean, cv
      }
    }
  }
}
function reset() { n=0; sum=0; sumsq=0; prev=-1 }
' "$TMPFILE" > "${TMPFILE}.beacons"

COUNT=$(wc -l < "${TMPFILE}.beacons")

if [ "$COUNT" -gt 0 ]; then
  echo "=========================================="
  echo "⚠  发现 $COUNT 个疑似 C2 Beacon 心跳 (CV < $CV_THRESHOLD, 样本 ≥ $MIN_SAMPLES)"
  echo "=========================================="
  echo "源IP            目标IP          端口    样本数  间隔均值(s)  CV"
  awk -F',' '{printf "%-16s %-15s %-7s %-7d %-11.1f %.3f\n", $1, $2, $3, $4, $5, $6}' "${TMPFILE}.beacons"
  echo ""
  echo "💡 处置建议: 对以上连接做进程排查 (ss -tnp | grep <目标IP>)，"
  echo "   确认后加入 ipset/iptables 封堵，或转人工狩猎报告"
else
  echo "✅ 未检测到规律性 C2 心跳 (阈值: CV<$CV_THRESHOLD, 样本≥$MIN_SAMPLES)"
fi

echo "BEACON_COUNT=$COUNT" >&2
rm -f "$TMPFILE" "${TMPFILE}.beacons"
exit 0
