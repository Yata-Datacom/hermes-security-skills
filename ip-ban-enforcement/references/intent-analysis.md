# 意图分析完整规格（SKILL.md 精简版存档）

本文件保存 SKILL.md 精简时压缩掉的功能细节，**全部能力均在此完整定义**，改配置只需编辑 `knowledge/intent_rules.yaml`。

## 意图 5 类

| 意图 | 标签 | 判定信号 | 处置建议 |
|------|------|----------|----------|
| recon | 🕵️ 侦察扫描 | unknownWebsite 批量、dirFilter/scannerFilter、404 刷量、TLS 握手打 HTTP、触碰 URI≥20、扫描器 UA | 封禁观察（30 天老化自动清理） |
| brute | 💥 暴力破解 | SSH Found≥5 次/跨≥2 天、attackCount、反复打同一路径、高频请求 | 长封 + fail2ban 联动 |
| exploit | 🎯 定向攻击 | sql/xss/oneWordTrojan/appFilter 规则、低频但精准命中业务路径 | 永久封 + 溯源分析 + 升级监控 |
| botnet | 🤖 僵尸网络 | defaultUaBlack/defaultIpBlack、海量 IP 单次触碰 | 子网段/ASN 级拦截 |
| abuse | 🕷️ 爬虫/CC滥用 | 高频正常请求命中 CC 规则 | 短封即可（CC 规则已限速） |

## 评分模型

```
得分 = Σ(规则权重 × min(命中数, 5)) + Σ(行为特征权重)
判定:
  total < min_score(3)                → unknown
  最高分/total ≥ dominance_ratio(0.5) → 该意图
  否则                                → mixed:top1+top2
置信度 = 最高分 / 总分
```

- **规则权重**（attack_logs 规则名 → 意图）：unknownWebsite{recon:2,botnet:1}、notFoundCount{recon:2}、dirFilter{recon:3}、scannerFilter{recon:3,botnet:1}、defaultUaBlack{botnet:3,recon:1}、attackCount{brute:2,abuse:1}、defaultIpBlack{botnet:2,recon:1}（WAF 内置 IP 信誉，非爆破特征！）、sql{exploit:4,brute:1}、xss{exploit:4}、oneWordTrojan{exploit:5}、appFilter{exploit:3,recon:1}、args{exploit:2}
- **行为特征**：ssh_found_high{brute:3}、ssh_found_persist{brute:2}、uri_wide{recon:2}、uri_narrow_repeat{brute:2,exploit:1}、high_freq{brute:1,abuse:1}、low_freq_precise{exploit:2}、tls_junk{recon:2}、scan_ua{recon:2,botnet:1}

## ⚠️ 已知坑（务必遵守）

1. **defaultIpBlack 不是爆破证据** — 它是 WAF 内置 IP 黑名单命中（已知恶意源），权重是 {botnet:2, recon:1}。早期版本误设为 {brute:2} 导致 15 个 IP 全部误判暴力破解。
2. **性能铁律** — 批量分析必须用 `collect_access_behaviors_all(target_ips)` 一次遍历 access.log + `collect_ssh_counts_all` 一次 zgrep。禁止逐 IP 调 `get_access_behaviors()`（O(IP×日志行数) 会超时，实测 653 IP 从超时优化到 4 秒）。
3. **attack_logs 双维度** — 必须同时 JOIN rules.db 和 rule_types.db 取规则名（COALESCE 会遮蔽类型名）。
4. **扫描器 UA 特征** — masscan/zgrab/nmap/nikto/sqlmap/python-requests/curl/wget/go-http-client/scanner/fofa/censys/shodan/majestic-12/semrush/ahrefs。

## 数据源

| 数据 | 来源 | 用途 |
|------|------|------|
| 规则命中 | attack_logs.db + rules.db + rule_types.db + ips.db | 规则权重 |
| URI/频率/UA/TLS垃圾 | OpenResty access.log | 行为特征 |
| SSH 失败 | fail2ban.log 系列（zgrep） | brute 特征 |
| GeoIP/ASN | ip-api.com（缓存） | 画像增强 |

## 命令速查

```bash
# 完整画像报告
python3 scripts/intent_analysis.py [--top N] [--days N] [--json] [--save]
# cron 静默：无定向攻击→一行摘要，有→详细（--save 存 ~/.hermes/cache/intent_history.json）
python3 scripts/intent_analysis.py --cron --save
# 单 IP 判定
python3 scripts/intent_lib.py <IP>
# 封禁打标（A 方案）：sync/daily/ips 自动写 iptables 注释 INTENT=<intent> <label> <date>
python3 scripts/ip_ban_sync.py sync
```

## 完整输出模板（SKILL.md 压缩版）

```
🎯 网络威胁意图分析 — YYYY-MM-DD HH:MM UTC+8 (窗口 7d)
==========================================================
📊 意图分布 (共 N 个攻击 IP):
   🎯 定向攻击          N (x.x%) ████
   💥 暴力破解          N (x.x%) ██
   🤖 僵尸网络          N (x.x%) ██
   🕵️ 侦察扫描        N (x.x%) ████████
   🌀 混合意图          N (x.x%) █
🚨 高危意图 (定向/爆破, N):
   🎯 定向攻击 IP — 置信N% [规则:appFilter×10, 反复打/xxx]
📋 攻击者画像 Top N:
   意图         IP                 置信     证据特征
   🎯 定向攻击   203.0.113.77     54%    规则:defaultUrlBlack×10
            └─ 建议: 永久封 + 溯源分析 + 升级监控
📈 趋势 (vs 上周): 定向 0 → 1 🔴 | 爆破 3 → 2 🟢
```
