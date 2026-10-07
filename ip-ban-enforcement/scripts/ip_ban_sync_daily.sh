#!/bin/bash
# ip_ban_sync_daily.sh — no_agent cron wrapper：每日攻击日志增量同步
# 修复历史 bug：script 字段带参数导致 "Script not found"（调度器不解析参数）
# 可移植：基于自身目录解析脚本路径，不写死绝对路径
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/ip_ban_sync.py" daily
