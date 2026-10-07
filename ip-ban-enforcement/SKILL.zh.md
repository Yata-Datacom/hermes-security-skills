---
name: ip-ban-enforcement
description: IP封禁分析与执行专家。遭受SSH爆破、Web攻击、SQLi/XSS注入、恶意扫描时自动分析攻击来源，联动fail2ban/WAF封禁，管理iptables PERMA-BAN链。支持攻击类型感知封禁（高危即封）、IPS签名检测、意图分析（侦察/爆破/定向/僵尸/爬虫）、每周同步、每日增量、ASN发现、GeoIP缓存、住宅ISP检测、老化验证、趋势追踪、自动维护和Bulletproof发现。
allowed-tools:
  - Read
  - Write
  - Bash
triggers:
  - "封禁这个 IP / ban 掉这个 IP"
  - "分析攻击来源 / 看看谁在攻击"
  - "PERMA-BAN 状态 / 当前封禁列表"
  - "子网段拦截 / 封整个段"
  - "同步封禁列表 (fail2ban/WAF → iptables)"
  - "去重清理 PERMA-BAN"
  - "查攻击 IP 分布 / GeoIP 分析"
  - "DMZHOST / Bulletproof 托管商分析"
  - "低频扫描检测 / 谁在扫 SSH"
  - "ASN 动态发现 / 可疑 ASN"
  - "住宅 ISP 检查 / 核实误封"
  - "趋势对比 / 周环比分析"
  - "SQL注入 / XSS / 攻击日志分级"
  - "IPS 签名检测 / 扫 access.log"
  - "意图分析 / 攻击者意图 / 扫描还是爆破"
  - "攻击画像 / 定向攻击识别 / intent 报告"
  - "自动维护 / 清理重复 / 老化清理 / PERMA-BAN 去重"
  - "cron 部署 / setup_cron / 一键装 cron"
  - "cron: 周日03:00同步 / 03:30增量 / 03:45IPS / 04:00ASN+意图 / 05:00维护"
---

# IP 封禁执行专家

> 🌐 语言：**中文**（本文件） · [**English**](SKILL.en.md)

管理 iptables PERMA-BAN 链，联动 fail2ban、WAF、攻击日志分级和 IPS 签名检测，多源自动封禁。脚本在 `scripts/`，配置在 `knowledge/`（YAML 即生效），完整规格见 `references/intent-analysis.md`。

## 核心能力

1. 多源联动封禁（fail2ban / WAF / 攻击日志 / 低频SSH → PERMA-BAN）
2. 攻击类型感知封禁（sql/xss/webshell 高危即封，dirFilter 中危 7天≥10次）
3. IPS 签名检测（access.log 11 类签名，≥2次/类别封禁）
4. 意图分析（规则权重+行为特征 → 5 类意图，封禁写 INTENT 注释）
5. 每日增量同步 + 低频 SSH 检测（7天≥10次）
6. 子网段防御 + ASN 动态发现（恶意 /24 拦截）
7. 住宅 ISP 识别（防误封）+ Bulletproof 升级 /24 拦截
8. 老化验证 + GeoIP 缓存 + 52 周趋势 + WAF 自适应
9. 自动维护（cleanup：去重 + 老化，DRY-RUN 安全预览）
10. 可移植 cron 部署（setup_cron.py 一键幂等创建全部 job）

## ⚠️ 研判铁律（最高优先级）

1. **已在 PERMA-BAN → 自动跳过**
2. **Bulletproof 托管 /24 → 完整拦截**
3. **Residential ISP /24 → 不封，标"疑似误封"**
4. **高危攻击（sql/xss/webshell）→ 1 次即封**
5. **低频扫描（≥10次/7天）→ 自动封禁**
6. **IPS 签名命中（≥2次/7天/类别）→ 自动封禁**
7. **白名单 → 绝对不封**（203.0.113.10、100.64.0.0/10 等）
8. **老化规则先验证日志 → 有活动保留，无才清理**
9. **不确定时给排查命令，不过度研判**

## ⚠️ 信息准确性要求（必须遵守）

1. **IP 归属必须查询确认**：GeoIP + WHOIS 双重验证
2. **封禁前必须确认不是白名单 IP**（含子网）
3. **不确定时标注"需进一步确认"**

## 研判流程（必须严格执行）

### Step 0：可移植部署（新环境一键装 cron）
```bash
python3 scripts/setup_cron.py            # 同步脚本 + 幂等创建 6 个 job
python3 scripts/setup_cron.py --dry-run  # 预览不动手
```
弱依赖：只调 `hermes cron create` CLI（Hermes 自带），同名 job 自动跳过。

### Step 1：每周全量同步（含攻击分级）
```bash
python3 scripts/ip_ban_sync.py sync
```
fail2ban/WAF/攻击分级/低频SSH/子网段 → PERMA-BAN，记趋势

### Step 2：每日攻击增量（高危当天封）
```bash
python3 scripts/ip_ban_sync.py daily
```
只扫 24h `attack_logs.db`，高危（sql/xss/webshell）即封

### Step 3：IPS 签名检测（漏网攻击）
```bash
python3 scripts/ip_ban_sync.py ips
```
扫 access.log 11 类签名 ≥2次/类别封禁（阈值 `knowledge/attack_signatures.yaml`）

### Step 4：ASN 动态发现
```bash
python3 scripts/ip_ban_asn_discovery.py
```
auth.log → WHOIS → ≥3次同ASN → RIPE 前缀 → 拦 /24
### Step 5：意图分析（封禁自动打标 + 独立画像报告）
```bash
# A: sync/daily 封禁自动写 INTENT 注释（iptables 可审计）
python3 scripts/ip_ban_sync.py sync
# B: 画像报告（--cron 静默 / --json 程序消费 / --save 存趋势）
python3 scripts/intent_analysis.py [--cron --save]
# 单 IP 判定
python3 scripts/intent_lib.py <IP>
```
意图 5 类：🕵️侦察 / 💥爆破 / 🎯定向 / 🤖僵尸 / 🕷️爬虫。评分=规则权重+行为特征，配置 `knowledge/intent_rules.yaml`。
⚠️ 性能铁律：批量分析必须一次遍历日志，禁止逐 IP 扫 access.log（超时）。
### Step 6：一键分析 + 快速状态（只读）
```bash
python3 scripts/ip_ban_sync.py analyze   # GeoIP/去重/Bulletproof/老化/趋势
python3 scripts/ip_ban_sync.py report    # 当前状态
```
### Step 6b：自动维护（去重 + 老化清理）
```bash
python3 scripts/ip_ban_sync.py cleanup        # DRY-RUN 预览
python3 scripts/ip_ban_sync.py cleanup --apply  # 执行删除
```
去重：同源多条保留最新；老化：单 IP >30 天无活跃 → 删。倒序删防漂移，全成功才 save。每日 05:00 cron。

### Step 7：手工维护
```bash
iptables -A PERMA-BAN -s <IP> -j DROP && netfilter-persistent save
iptables -A PERMA-BAN -s <子网> -m comment --comment "原因" -j DROP && netfilter-persistent save
iptables -D PERMA-BAN <序号> && netfilter-persistent save
```

## 输出格式（必须严格遵守）

完整模板见 `references/output-templates.md`。速览：

```
🛡️ 同步: 📋N+N | 🔒f2b:N | 🛡️WAF:N | 🎯高危N | 🔎SSH:N | 🚨新IP | 🔢N+N | 📈+N
🛡️ IPS: 类别 | 🚨命中N,新封N: IP — sql×N,xss×N
🎯 意图: 分布(共N) | 🚨高危: IP 置信N% [证据] | 📋TopN | 📈定向0→1🔴
📡 分析: 规则N | 重复N | IP N | 子网N | 国家/ASN | 住宅N | BP N | 老化N
🧹 维护: 待清理N条 | ✅/✨无需清理 | 🔢N+N
🛡️ 部署: [1/3]脚本 [2/3]幂等6job [3/3]验证 | ✅新增N个
```
