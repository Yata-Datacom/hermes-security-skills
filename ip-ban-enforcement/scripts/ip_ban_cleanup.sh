#!/bin/bash
# ip_ban_cleanup.sh — no_agent cron wrapper：PERMA-BAN 每日自动维护
# 去重（同源多条保留最新）+ 老化清理（>30天无活跃日志的 IP）
# 可移植：基于自身目录解析脚本路径，不写死绝对路径
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/ip_ban_sync.py" cleanup --apply
