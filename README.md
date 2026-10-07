<div align="center">

# Security Operations Skills

**Two drop-in skills for AI agents — IP-ban orchestration with threat-intent analysis, and Linux threat hunting (ICMP/DNS tunnels, C2 beacons, DGA domains).**

<sub>[**English**](README.md) · [**简体中文**](README.zh-CN.md)</sub>

<img src="https://img.shields.io/badge/License-MIT-8FBCBB?style=flat-square" alt="MIT" />
<img src="https://img.shields.io/badge/Python-3.9%2B-8FBCBB?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+" />
<img src="https://img.shields.io/badge/Platform-Linux-88C0D0?style=flat-square&logo=linux&logoColor=white" alt="Linux" />
<img src="https://img.shields.io/badge/Role-Defensive%20Security-5E81AC?style=flat-square" alt="Defensive security" />

</div>

Two skills, each a self-contained package (`SKILL.md` + `scripts/` + `knowledge/` + `references/`) that an AI agent can load directly. Both are production-tested versions, genericised and sanitised for public release.

| Skill | Role | Core capabilities |
|---|---|---|
| [`ip-ban-enforcement`](./ip-ban-enforcement) | Attack-source triage and ban execution | Six-mode ban engine (full sync / daily delta / IPS signature scan / data analysis / trend report / auto maintenance); **threat-intent analysis engine** (4 features → 5 intent classes + confidence; dual output: real-time ban tagging + daily attacker profile); ASN discovery with subnet-level blocking; residential-ISP false-positive exemption; GeoIP cache; aging verification |
| [`linux-threat-hunter`](./linux-threat-hunter) | Advanced Linux threat hunting | Trusts raw packet length and behaviour, **not** vendor alerts: ICMP tunnel / DNS tunnel / C2 beacon (interval coefficient of variation) / DGA domains (4-dimension score) / anomalous egress; behaviour scorer; auto-block (OUTPUT + FORWARD chains, timed release); self-learning case library |

## Design stance

- **Raw evidence only** — no trust in firewall vendor alerts; only capture lengths, byte ratios and raw log lines
- **Degrade, never fail** — `tshark` → `tcpdump`; `ipset` → plain `iptables`; `pyyaml` → built-in default rules
- **Dry-run by default** — destructive actions (ban deletion, rule cleanup) need an explicit flag to write
- **Configuration first** — rules, thresholds, signatures and subnets all live in editable YAML, effective without touching code
- **Code carries its own fallback** — missing config still runs, because sensible defaults are inline

## Install

Both directories are standard skill packages:

```bash
# e.g. for Hermes Agent: drop them into the skills directory
cp -r ip-ban-enforcement linux-threat-hunter ~/.hermes/skills/
```

Or grab the packaged zips from [Releases](../../releases).

Each skill ships two documents with identical content — `SKILL.md` (Chinese) and `SKILL.en.md` (English). Pick your language; the runtime loads `SKILL.md` by convention.

**It runs without you hand-editing anything** — every config file falls back to built-in defaults (`pyyaml` missing also falls back). Three things are *optional* to tune:

| Config | Required? | Notes |
|---|---|---|
| WAF DB / access-log paths<br>`ip-ban-enforcement/knowledge/thresholds.yaml` | **No** | Ships with generic defaults (`/var/lib/waf/`, `/var/log/nginx/access.log`). Where your actual DB and logs live is best **discovered on the spot by your AI agent** — it has shell access and can trace the process, panel install dir and config files, which beats hand-copying a path |
| Malicious subnet list<br>`ip-ban-enforcement/knowledge/subnets.yaml` | **No preset needed** | This is a **self-growing list**: hits are written in, aging reclaims them. Starting empty is fine — you do not need to copy someone else's intel |
| Behaviour scoring weights & thresholds<br>`linux-threat-hunter/knowledge/rules.yaml` | **Reference only** | What ships was tuned in the author's environment — **for reference only**. Your traffic baseline differs; recalibrate against your own |

> In short: install it and start using it. Config is adjusted as you go, not filled in before you begin.

## Requirements

- `python3` (standard library mostly) + optional `pyyaml`
- Capture: `tcpdump` (required) / `tshark` (optional, richer fields)
- Blocking: `ipset` (optional) / `iptables`
- Attribution: system `whois`, `ip-api.com` (batch GeoIP)

## Disclaimer

- These are **defensive** security tools: analyse attacks against servers you run, enforce bans, detect covert channels. Use them only on systems you are authorised to manage.
- Every IP, subnet, path and timezone example in this repository is a placeholder or a documentation value (RFC 5737 / private ranges). No real environment data is included.
- MIT License.
