# Security Operations Skills（Hermes Agent 技能包）

两个可直接装载的 AI Agent 技能（Skill），覆盖**攻击来源研判与封禁执行**、**Linux 威胁狩猎与隐蔽信道检测**。均为实际生产环境使用过的版本，已做通用化与脱敏处理，随包提供降级方案，可在普通发行版上直接运行。

| 技能 | 定位 | 核心能力 |
|---|---|---|
| [`ip-ban-enforcement`](./ip-ban-enforcement) | IP 封禁分析与执行 | 六模式合一的封禁引擎（全量同步 / 每日增量 / IPS 签名检测 / 数据分析 / 状态趋势 / 自动维护）；**威胁意图分析引擎**（4 维特征 → 5 类意图 + 置信度，双出口：封禁实时打标 + 每日攻击者画像）；ASN 动态发现与网段级拦截；住宅 ISP 误封豁免；GeoIP 缓存；老化验证与趋势追踪 |
| [`linux-threat-hunter`](./linux-threat-hunter) | Linux 高级威胁狩猎 | 不依赖任何防火墙厂商告警，只用原始包长与行为特征：ICMP 隧道 / DNS 隧道 / C2 信标（间隔变异系数）/ DGA 域名（四维评分）/ 异常外联检测；行为评分器；自动封堵（本机 + 转发双链，定时解封）；案例库自学习 |

## 设计取向

- **只信原始证据**：不信厂商告警，只信抓包长度、字节比与日志原文
- **多后端降级**：抓包 `tshark` 缺失自动退 `tcpdump`；封堵 `ipset` 缺失自动退纯 `iptables`；规则 `pyyaml` 缺失回退内置默认规则
- **默认预演**：破坏性操作（封禁删除、规则清理）默认 dry-run，需显式参数才写入
- **可配置优先**：规则、阈值、签名、网段全部外置为 YAML，编辑即生效，不用改代码
- **配置与代码同源**：代码内置兜底默认值，配置缺失也能跑

## 装载方式

两个目录都是标准技能包结构（`SKILL.md` + `scripts/` + `knowledge/` + `references/`）：

```bash
# 以 Hermes Agent 为例：把技能目录放进技能库
cp -r ip-ban-enforcement linux-threat-hunter ~/.hermes/skills/

# 或直接使用随包 zip（与仓库同结构）
```

部署前请按你的环境修改：

1. `ip-ban-enforcement/knowledge/thresholds.yaml` —— WAF 数据库与访问日志路径（示例为 `/var/lib/waf/`、`/var/log/nginx/access.log`）、白名单
2. `ip-ban-enforcement/knowledge/subnets.yaml` —— 恶意网段列表（仓库内为示例占位，请填入你自己的情报）
3. `linux-threat-hunter/knowledge/rules.yaml` —— 行为评分权重与阈值

## 依赖

- `python3`（标准库为主）+ 可选 `pyyaml`
- 抓包：`tcpdump`（必需）/ `tshark`（可选，功能更完整）
- 封堵：`ipset`（可选）/ `iptables`
- 归属查询：系统 `whois`、`ip-api.com`（批量 GeoIP）

## 声明

- 本仓库为**防御性**安全工具：用于分析针对自己服务器的攻击、执行封禁、检测隐蔽信道。请仅在你有权管理的系统上使用。
- 仓库内所有 IP、网段、路径、时区示例均为占位或文档地址（RFC 5737 / 私有段），不含任何真实环境数据。
- MIT License.
