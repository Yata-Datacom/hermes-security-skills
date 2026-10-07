---
name: ip-ban-enforcement
description: IP ban analysis and enforcement expert. When SSH brute force, web attacks, SQLi/XSS injection or malicious scanning occurs, it analyses the attack sources automatically, drives fail2ban/WAF bans and manages the iptables PERMA-BAN chain. Supports attack-type-aware banning (high-risk banned on first hit), IPS signature scanning, intent analysis (recon / brute force / targeted / botnet / crawler), weekly sync, daily delta, ASN discovery, GeoIP cache, residential-ISP detection, aging verification, trend tracking, automatic maintenance and bulletproof-hosting discovery.
allowed-tools:
  - Read
  - Write
  - Bash
triggers:
  - "ban this IP / block this IP"
  - "analyse the attack source / who is attacking us"
  - "PERMA-BAN status / current ban list"
  - "block a subnet / block the whole range"
  - "sync ban lists (fail2ban/WAF -> iptables)"
  - "dedupe and clean up PERMA-BAN"
  - "attack IP distribution / GeoIP analysis"
  - "bulletproof hosting analysis"
  - "low-frequency scanning detection / who is scanning SSH"
  - "ASN discovery / suspicious ASN"
  - "residential ISP check / verify a false positive"
  - "trend comparison / week-over-week"
  - "SQL injection / XSS / attack log grading"
  - "IPS signature scan / scan access.log"
  - "intent analysis / what is the attacker after"
  - "attacker profile / targeted-attack identification / intent report"
  - "automatic maintenance / dedupe / aging cleanup"
  - "cron deployment / setup_cron / install cron jobs"
  - "cron: Sunday 03:00 sync / 03:30 delta / 03:45 IPS / 04:00 ASN+intent / 05:00 maintenance"
---

> 🌐 Language: **English** (this file) · [**中文**](SKILL.md)

# IP Ban Enforcement

Manages the iptables PERMA-BAN chain and drives fail2ban, a WAF, attack-log grading and IPS signature scanning for multi-source automatic banning. Scripts live in `scripts/`, configuration in `knowledge/` (YAML, effective immediately), and the full specification is in `references/intent-analysis.md`.

## Core capabilities

1. Multi-source coordinated banning (fail2ban / WAF / attack logs / low-frequency SSH → PERMA-BAN)
2. Attack-type-aware banning (sql/xss/webshell banned on first hit; dirFilter medium-risk at ≥10 hits in 7 days)
3. IPS signature scanning (11 signature classes over access.log, ≥2 hits per class to ban)
4. Intent analysis (rule weights + behaviour features → 5 intent classes, INTENT comment written into the ban rule)
5. Daily delta sync + low-frequency SSH detection (≥10 hits in 7 days)
6. Subnet defence + ASN discovery (malicious /24 blocking)
7. Residential-ISP recognition (false-positive protection) + bulletproof-hosting upgrade to /24 blocking
8. Aging verification + GeoIP cache + 52-week trend + WAF adaptation
9. Automatic maintenance (cleanup: dedupe + aging, DRY-RUN safety preview)
10. Portable cron deployment (`setup_cron.py` creates every job idempotently in one shot)

## ⚠️ Iron rules of triage (highest priority)

1. **Already in PERMA-BAN → skip automatically**
2. **Bulletproof-hosting /24 → block the whole range**
3. **Residential ISP /24 → do not ban, mark as "possible false positive"**
4. **High-risk attack (sql/xss/webshell) → ban on the first hit**
5. **Low-frequency scanning (≥10 hits / 7 days) → ban automatically**
6. **IPS signature hit (≥2 hits / 7 days / class) → ban automatically**
7. **Whitelist → never ban** (203.0.113.10, 100.64.0.0/10, …)
8. **Aging rules verify the log first → keep if there is activity, clean only when there is none**
9. **When unsure, give investigation commands — do not over-interpret**

## ⚠️ Accuracy requirements (mandatory)

1. **IP ownership must be queried and confirmed**: GeoIP + WHOIS double check
2. **Before banning, confirm it is not a whitelisted IP** (subnets included)
3. **When unsure, mark "needs further confirmation"**

## Triage workflow (must be followed strictly)

### Step 0: Portable deployment (install cron in a new environment)
```bash
python3 scripts/setup_cron.py            # sync scripts + create the 6 jobs idempotently
python3 scripts/setup_cron.py --dry-run  # preview without touching anything
```
Light dependency: it only calls the `hermes cron create` CLI (shipped with Hermes); jobs with the same name are skipped automatically.

### Step 1: Weekly full sync (with attack grading)
```bash
python3 scripts/ip_ban_sync.py sync
```
fail2ban / WAF / attack grading / low-frequency SSH / subnets → PERMA-BAN, trend recorded

### Step 2: Daily attack delta (high-risk banned the same day)
```bash
python3 scripts/ip_ban_sync.py daily
```
Scans only the last 24 h of `attack_logs.db`; high-risk (sql/xss/webshell) banned immediately

### Step 3: IPS signature scanning (attacks that slipped through)
```bash
python3 scripts/ip_ban_sync.py ips
```
Scans access.log for 11 signature classes; ban at ≥2 hits per class (thresholds in `knowledge/attack_signatures.yaml`)

### Step 4: ASN discovery
```bash
python3 scripts/ip_ban_asn_discovery.py
```
auth.log → WHOIS → ≥3 hits from the same ASN → RIPE prefixes → block the /24

### Step 5: Intent analysis (automatic ban tagging + standalone profile report)
```bash
# A: sync/daily write INTENT comments into ban rules (auditable in iptables)
python3 scripts/ip_ban_sync.py sync
# B: profile report (--cron silent / --json for programs / --save to store trends)
python3 scripts/intent_analysis.py [--cron --save]
# single-IP verdict
python3 scripts/intent_lib.py <IP>
```
Five intent classes: 🕵️ recon / 💥 brute force / 🎯 targeted / 🤖 botnet / 🕷️ crawler. Score = rule weights + behaviour features, configured in `knowledge/intent_rules.yaml`.
⚠️ Performance rule: batch analysis must traverse the log once; never scan access.log per IP (it will time out).

### Step 6: One-shot analysis + quick status (read-only)
```bash
python3 scripts/ip_ban_sync.py analyze   # GeoIP / dedupe / bulletproof / aging / trend
python3 scripts/ip_ban_sync.py report    # current status
```

### Step 6b: Automatic maintenance (dedupe + aging cleanup)
```bash
python3 scripts/ip_ban_sync.py cleanup          # DRY-RUN preview
python3 scripts/ip_ban_sync.py cleanup --apply  # actually delete
```
Dedupe: for duplicates from one source keep the newest; aging: a single IP with no activity for >30 days is deleted. Deletions run in reverse order to avoid index drift, and the file is saved only if every deletion succeeded. Runs daily at 05:00 via cron.

### Step 7: Manual maintenance
```bash
iptables -A PERMA-BAN -s <IP> -j DROP && netfilter-persistent save
iptables -A PERMA-BAN -s <subnet> -m comment --comment "reason" -j DROP && netfilter-persistent save
iptables -D PERMA-BAN <index> && netfilter-persistent save
```

## Output format (must be followed strictly)

The full template is in `references/output-templates.md`. Quick view:

```
🛡️ Sync: 📋N+N | 🔒f2b:N | 🛡️WAF:N | 🎯high-risk N | 🔎SSH:N | 🚨new IPs | 🔢N+N | 📈+N
🛡️ IPS: classes | 🚨N hits, N newly banned: IP — sql×N, xss×N
🎯 Intent: distribution (total N) | 🚨high-risk: IP confidence N% [evidence] | 📋Top N | 📈targeted 0→1🔴
📡 Analysis: rules N | duplicates N | IPs N | subnets N | countries/ASN | residential N | bulletproof N | aging N
🧹 Maintenance: N pending | ✅/✨nothing to clean | 🔢N+N
🛡️ Deployment: [1/3] scripts [2/3] idempotent 6 jobs [3/3] verify | ✅N created
```
