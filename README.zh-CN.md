<div align="center">

# 安全运营技能包

**两个可直接装载的 AI Agent 技能：IP 封禁编排与攻击意图分析、Linux 威胁狩猎（ICMP/DNS 隧道、C2 信标、DGA 域名）。**

<sub>[**English**](README.md) · [**简体中文**](README.zh-CN.md)</sub>

<img src="https://img.shields.io/badge/License-MIT-8FBCBB?style=flat-square" alt="MIT" />
<img src="https://img.shields.io/badge/Python-3.9%2B-8FBCBB?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+" />
<img src="https://img.shields.io/badge/Platform-Linux-88C0D0?style=flat-square&logo=linux&logoColor=white" alt="Linux" />

</div>

两个技能，每个都是自包含的技能包（`SKILL.md` + `scripts/` + `knowledge/` + `references/`），AI Agent 可直接装载。均为生产环境使用过的版本，已做通用化与脱敏处理。

| 技能 | 定位 | 核心能力 |
|---|---|---|
| [`ip-ban-enforcement`](./ip-ban-enforcement) | 攻击来源研判与封禁执行 | 六合一封禁引擎（全量同步 / 每日增量 / IPS 签名检测 / 数据分析 / 状态趋势 / 自动维护）；**威胁意图分析引擎**（4 维特征 → 5 类意图 + 置信度，双出口：封禁实时打标 + 每日攻击者画像）；ASN 动态发现与网段级拦截；住宅 ISP 误封豁免；GeoIP 缓存；老化验证 |
| [`linux-threat-hunter`](./linux-threat-hunter) | Linux 高级威胁狩猎 | 不信厂商告警，只信原始包长与行为特征：ICMP 隧道 / DNS 隧道 / C2 信标（间隔变异系数）/ DGA 域名（四维评分）/ 异常外联；行为评分器；自动封堵（本机 + 转发双链，定时解封）；案例库自学习 |

## 设计取向

- **只信原始证据** —— 不信防火墙厂商告警，只信抓包长度、字节比与日志原文
- **只降级，不失败** —— `tshark` 缺则退 `tcpdump`；`ipset` 缺则退纯 `iptables`；`pyyaml` 缺则回退内置规则
- **默认预演** —— 破坏性操作（封禁删除、规则清理）需显式参数才写入
- **配置优先** —— 规则、阈值、签名、网段全部外置为 YAML，编辑即生效，不用改代码
- **代码自带兜底** —— 配置缺失也能跑，因为缺省值内联在代码里

## 装载

两个目录都是标准技能包结构：

```bash
# 以 Hermes Agent 为例：放进技能目录
cp -r ip-ban-enforcement linux-threat-hunter ~/.hermes/skills/
```

或直接取 [Releases](../../releases) 里打包好的 zip。

**无需手工改配置就能跑** —— 每个配置文件都会回退到内置缺省（`pyyaml` 缺失也会回退）。下面三处都属于**可选**调整：

| 配置 | 是否必须 | 说明 |
|---|---|---|
| WAF 数据库 / 访问日志路径<br>`ip-ban-enforcement/knowledge/thresholds.yaml` | **不必手填** | 缺省是通用路径（`/var/lib/waf/`、`/var/log/nginx/access.log`）。实际的库文件与日志在哪，**交给你的 AI Agent 现场探测**即可 —— 它有 shell 权限，可直接反查进程、面板安装目录与配置文件，比手抄更准 |
| 恶意网段列表<br>`ip-ban-enforcement/knowledge/subnets.yaml` | **无需预置** | 这是**自增长列表**：命中即写入、老化自动回收。起手留空也能跑，不需要拷贝别人的情报 |
| 行为评分权重与阈值<br>`linux-threat-hunter/knowledge/rules.yaml` | 仅作**参考** | 仓库里带的是作者环境调出来的**参考值 —— 仅供参考**。你的流量基线不同，应按自己的环境重新校准 |

> 装上去就能开始用，配置是「用着用着按需调」，不是「装之前必须先填表」。

## 依赖

- `python3`（以标准库为主）+ 可选 `pyyaml`
- 抓包：`tcpdump`（必需）/ `tshark`（可选，字段更完整）
- 封堵：`ipset`（可选）/ `iptables`
- 归属查询：系统 `whois`、`ip-api.com`（批量 GeoIP）

## 声明

- 本仓库为**防御性**安全工具：用于分析针对自己服务器的攻击、执行封禁、检测隐蔽信道。请仅在你有权管理的系统上使用。
- 仓库内所有 IP、网段、路径、时区示例均为占位或文档地址（RFC 5737 / 私有段），不含任何真实环境数据。
- MIT License.
