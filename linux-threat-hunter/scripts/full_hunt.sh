#!/bin/bash
# full_hunt.sh — 一键威胁狩猎工作流：抓包 → 隧道检测 → 日志评分 → 封堵
# 用法: sudo ./full_hunt.sh [网卡] [抓包时长秒数]
# 示例: sudo ./full_hunt.sh eth0 300

set -o pipefail

INTERFACE="${1:-eth0}"
CAPTURE_DURATION="${2:-120}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT="/tmp/threat_hunt_report_${TIMESTAMP}.txt"
PCAP_FILE="/tmp/live_hunt_$$.pcap"

# 前置检查
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: 需要 root 权限执行 (抓包需要 sudo)" >&2
  exit 1
fi

# 前置检查: tcpdump 必须; tshark 可选（检测脚本会自动降级到 tcpdump）
if ! command -v tcpdump &>/dev/null; then
  echo "ERROR: tcpdump 未安装" >&2
  exit 1
fi
if ! command -v tshark &>/dev/null; then
  echo "ℹ  tshark 未安装 — 隧道检测将降级使用 tcpdump (apt-get install tshark 可获得完整字段)" >&2
fi

# 写报告头
{
  echo "=========================================="
  echo "   Linux 威胁狩猎报告"
  echo "   时间: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "   网卡: $INTERFACE | 抓包: ${CAPTURE_DURATION}s | 主机: $(hostname)"
  echo "=========================================="
  echo ""
} > "$REPORT"

# ----- 阶段1: 抓取实时流量 -----
echo "[1/5] 正在抓取 ${CAPTURE_DURATION}s 流量 ($INTERFACE)..." | tee -a "$REPORT"
timeout "$CAPTURE_DURATION" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" -s 0 2>/dev/null
TCPDUMP_EXIT=$?

if [ ! -s "$PCAP_FILE" ]; then
  echo "⚠  tcpdump 未抓到数据包 (退出码: $TCPDUMP_EXIT)" | tee -a "$REPORT"
  echo "   可能原因: 网卡不对或没有流量经过" | tee -a "$REPORT"
  rm -f "$PCAP_FILE"
  # 阶段2-3可以尝试实时抓取，但至少报错
fi

PCAP_SIZE=$(du -h "$PCAP_FILE" 2>/dev/null | cut -f1)
echo "✅ 抓包完成: ${PCAP_SIZE:-0B}" >> "$REPORT"
echo "" >> "$REPORT"

# ----- 阶段2: ICMP 隧道检测 (分析已抓取的 pcap) -----
echo "[2/5] 检测 ICMP 隧道..." | tee -a "$REPORT"
echo "--- ICMP 隧道检测 ---" >> "$REPORT"
if [ -s "$PCAP_FILE" ]; then
  "$SCRIPT_DIR/detect_icmp_tunnel.sh" -r "$PCAP_FILE" >> "$REPORT" 2>&1
else
  echo "⚠  无 pcap 文件，尝试实时抓取 30s..." >> "$REPORT"
  "$SCRIPT_DIR/detect_icmp_tunnel.sh" "$INTERFACE" 30 >> "$REPORT" 2>&1
fi
echo "" >> "$REPORT"

# ----- 阶段3: DNS 隧道检测 -----
echo "[3/5] 检测 DNS 隧道..." | tee -a "$REPORT"
echo "--- DNS 隧道检测 ---" >> "$REPORT"
if [ -s "$PCAP_FILE" ]; then
  "$SCRIPT_DIR/detect_dns_tunnel.sh" "$PCAP_FILE" >> "$REPORT" 2>&1
else
  echo "⚠  无 pcap 文件，跳过 DNS 隧道检测" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ----- 阶段4: 防火墙日志评分 -----
echo "[4/5] 分析防火墙日志..." | tee -a "$REPORT"
LOG_FOUND=false
for LOG_DIR in "/var/log/firewall" "/var/log/ufw" "/var/log/suricata" "/var/log/syslog"; do
  if [ -d "$LOG_DIR" ]; then
    LATEST_LOG=$(ls -t "$LOG_DIR"/*.csv "$LOG_DIR"/*.log "$LOG_DIR"/*.json 2>/dev/null | head -1)
    if [ -n "$LATEST_LOG" ]; then
      echo "--- 行为评分: $(basename "$LATEST_LOG") ---" >> "$REPORT"
      python3 "$SCRIPT_DIR/log_hunter.py" "$LATEST_LOG" >> "$REPORT" 2>&1
      LOG_FOUND=true
      break
    fi
  fi
done
if [ "$LOG_FOUND" = false ]; then
  echo "ℹ  未找到防火墙日志文件，跳过行为评分" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ----- 阶段5: 自动封堵 -----
echo "[5/7] 执行自动封堵..." | tee -a "$REPORT"
echo "--- 自动封堵 ---" >> "$REPORT"

# 从报告中提取需封禁的 IP (排除标记行)
BLOCK_IPS=$(sed -n '/###BLOCK_LIST_START###/,/###BLOCK_LIST_END###/p' "$REPORT" | \
  grep -v '###BLOCK_LIST' | grep -E '^[0-9]+\.([0-9]+\.){2}[0-9]+$')

if [ -n "$BLOCK_IPS" ]; then
  echo "$BLOCK_IPS" | "$SCRIPT_DIR/auto_block.sh" >> "$REPORT" 2>&1
else
  echo "ℹ  无需要封禁的 IP" >> "$REPORT"
fi

# ----- 阶段6: Beacon 心跳检测 (C2 时间规律) -----
echo "[6/7] 检测 C2 Beacon 心跳..." | tee -a "$REPORT"
echo "--- Beacon 检测 ---" >> "$REPORT"
if [ -s "$PCAP_FILE" ]; then
  "$SCRIPT_DIR/detect_beacon.sh" "$PCAP_FILE" >> "$REPORT" 2>&1
else
  echo "⚠  无 pcap 文件，跳过 Beacon 检测" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ----- 阶段7: DGA 域名检测 -----
echo "[7/7] 检测 DGA 随机域名..." | tee -a "$REPORT"
echo "--- DGA 检测 ---" >> "$REPORT"
if [ -s "$PCAP_FILE" ]; then
  python3 "$SCRIPT_DIR/detect_dga.py" "$PCAP_FILE" >> "$REPORT" 2>&1
else
  echo "⚠  无 pcap 文件，跳过 DGA 检测" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ----- 报告结尾 -----
echo "" >> "$REPORT"
echo "==========================================" >> "$REPORT"
echo " 报告位置: $REPORT" >> "$REPORT"
echo "==========================================" >> "$REPORT"

# 清理
rm -f "$PCAP_FILE"

# 输出报告
cat "$REPORT"
exit 0
