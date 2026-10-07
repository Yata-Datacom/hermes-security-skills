#!/bin/bash
# intent_analysis_cron.sh — no_agent cron wrapper：每日意图分析画像报告
# --cron 静默：无定向攻击→一行摘要；有→详细报告。--save 存趋势到 ~/.hermes/cache/intent_history.json
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/intent_analysis.py" --cron --save
