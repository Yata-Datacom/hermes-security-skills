#!/bin/bash
# auto_block.sh — 读取 IP 列表，封禁 24 小时（多后端降级）
# 用法: cat blocklist.txt | ./auto_block.sh
#
# v2.1 修复/优化:
#   - 同时拦截 OUTPUT（本机外联——C2/隧道/外泄方向）和 FORWARD（转发流量）
#   - 后端降级: ipset 存在 → ipset(timeout 自动解封)
#              无 ipset  → 纯 iptables 单条规则 + 状态文件跟踪 24h 过期清理
#     （ParrotOS/Kali 有 ipset；普通发行版无 ipset 也能用）

IPSET_NAME="threat_hunter_blocklist"
TIMEOUT=86400
STATE_FILE="/var/tmp/threat_hunter_blocks.txt"   # 纯 iptables 模式的过期跟踪

# ── 后端选择 ──
if command -v ipset >/dev/null 2>&1; then
  BACKEND="ipset"
else
  BACKEND="iptables"
fi
echo "ℹ  封堵后端: $BACKEND" >&2

if [ "$BACKEND" = "ipset" ]; then
  # ── ipset 模式：hash:ip + timeout，自动解封 ──
  ipset create "$IPSET_NAME" hash:ip timeout "$TIMEOUT" -exist 2>/dev/null

  # OUTPUT + FORWARD 双链（幂等）
  for CHAIN in OUTPUT FORWARD; do
    iptables -C "$CHAIN" -m set --match-set "$IPSET_NAME" dst -j DROP 2>/dev/null || \
      iptables -I "$CHAIN" -m set --match-set "$IPSET_NAME" dst -j DROP
  done

  BLOCKED=0; SKIPPED=0
  while read -r raw_ip; do
    ip=$(echo "$raw_ip" | xargs)
    [ -z "$ip" ] && continue
    if echo "$ip" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)'; then
      echo "⚠  跳过内网地址: $ip" >&2; ((SKIPPED++)); continue
    fi
    if ipset add "$IPSET_NAME" "$ip" timeout "$TIMEOUT" 2>/dev/null; then
      echo "🔒 已封禁: $ip (24h 自动解封, OUTPUT+FORWARD)"
      logger -t threat-hunter "BLOCKED $ip (threat-hunter auto-block)"
      ((BLOCKED++))
    fi
  done

  CURRENT=$(ipset list "$IPSET_NAME" 2>/dev/null | grep -cE '^[0-9]+\.[0-9]+')
  echo "---"
  echo "✅ 封禁完成: $BLOCKED 个IP | 跳过: $SKIPPED 个 | 当前总数: $CURRENT"
  exit 0
fi

# ══════════════ 纯 iptables 降级模式 ══════════════
# 先清理过期规则（>24h）
NOW=$(date +%s)
if [ -f "$STATE_FILE" ]; then
  while IFS='|' read -r ts ip; do
    [ -z "$ip" ] && continue
    if [ $((NOW - ts)) -ge "$TIMEOUT" ]; then
      for CHAIN in OUTPUT FORWARD; do
        iptables -D "$CHAIN" -d "$ip" -j DROP 2>/dev/null
      done
      echo "♻️  已解封过期 IP: $ip" >&2
    else
      echo "$ts|$ip" >> "${STATE_FILE}.new"
    fi
  done < "$STATE_FILE"
  mv "${STATE_FILE}.new" "$STATE_FILE" 2>/dev/null || rm -f "$STATE_FILE"
fi

BLOCKED=0; SKIPPED=0
while read -r raw_ip; do
  ip=$(echo "$raw_ip" | xargs)
  [ -z "$ip" ] && continue
  if echo "$ip" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)'; then
    echo "⚠  跳过内网地址: $ip" >&2; ((SKIPPED++)); continue
  fi

  # 已封禁则跳过（幂等）
  if iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null; then
    continue
  fi

  for CHAIN in OUTPUT FORWARD; do
    iptables -I "$CHAIN" -d "$ip" -j DROP 2>/dev/null
  done
  echo "$(date +%s)|$ip" >> "$STATE_FILE"
  echo "🔒 已封禁: $ip (24h, iptables模式)"
  logger -t threat-hunter "BLOCKED $ip (threat-hunter auto-block iptables)"
  ((BLOCKED++))
done

CURRENT=$(iptables -L OUTPUT -n 2>/dev/null | grep -c '^DROP')
echo "---"
echo "✅ 封禁完成: $BLOCKED 个IP | 跳过: $SKIPPED 个 | OUTPUT链规则数: $CURRENT"
echo "⚠  当前为 iptables 降级模式（无 ipset）。建议 apt-get install ipset 获取自动超时管理。" >&2
exit 0
