# 输出格式完整模板（SKILL.md 精简版存档）

SKILL.md 的「输出格式」章节仅保留此文件的引用与一行速览，完整模板在本文件。

## 同步报告
```
🛡️ IP 封禁同步报告 — YYYY-MM-DD HH:MM UTC+8
📋 PERMA-BAN 已有: N IP + N 子网段
🔒 fail2ban: N (新N) | 🛡️ WAF: N (新N)
🎯 攻击日志(7天): 高危 N (新N) | 中危 N (新N)
🔎 低频SSH(7天≥N次): N (新N) | 🌐 恶意子网段: N已拦 N待加
🚨 N 新 IP 加入 PERMA-BAN… 📊 新增 N IP + N 子网段
🔢 最终: N IP + N 子网段 | 📈 趋势: +N
```

## IPS 检测报告
```
🛡️ IPS 签名检测 — YYYY-MM-DD HH:MM UTC+8 (窗口 Nd)
📊 类别: sql N / xss N / ... | 🚨 命中 N IP, 新封 N: 🆕 IP — sql×N,xss×N
```

## 意图分析报告
```
🎯 意图分析 — YYYY-MM-DD HH:MM UTC+8 (窗口 7d)
📊 分布(共N): 🎯定向 N | 💥爆破 N | 🤖僵尸 N | 🕵️扫描 N | 🌀混合 N
🚨 高危(定向/爆破): 🎯 IP — 置信N% [证据]
📋 画像 Top N: 意图/IP/置信/证据 — 🎯 1.2.3.4 54% appFilter×10 └→永久封+溯源
📈 趋势: 定向 0→1 🔴
```

## 分析报告
```
📡 规则 N | 🔍 重复 N | 🌐 IP N | 子网 N | 📊 国家Top10/ASN Top5
🏠 住宅 ISP N | 🛡️ Bulletproof N | ⏳ 老化 N | 📈 趋势 N 次
```

## 自动维护报告（cleanup）
```
🧹 PERMA-BAN 自动维护 — YYYY-MM-DD HH:MM UTC+8
🔍 待清理 N 条:
   #1312 203.0.113.45 (老化44d)
   #5 203.0.113.0/24 (重复)
   ✅ 已删 #5 ... | 💾 保存: 成功
   ✨ 无需清理：无重复、无老化（平时静默）
🔢 PERMA-BAN 最终: N IP + N 子网段
```

## cron 部署报告（setup_cron）
```
🛡️ ip-ban-enforcement cron 部署
[1/3] 同步脚本 → ~/.hermes/scripts/
[2/3] 创建 6 个 cron job（幂等）
  ✅ Weekly IP Ban Sync    已存在 (id=xxx) / ✅ 创建成功
[3/3] 验证 — 当前活跃 job 总数: N
✅ 部署完成 — 新增 N 个，其余已存在
```
