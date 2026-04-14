# 未知网络流量应用协议识别系统 × MyBot 整合改造开发文档（设计稿）

> 目的：把当前仓库中的两部分代码（“未知网络流量应用协议识别系统”框架 + `mybot-main`）整合为一个可端到端运行的离线批处理系统。
>
> 重要说明：本文档是“改造/集成设计文档 + 开发任务拆解 + 接口契约”。**本次不修改任何代码**，仅作为后续实现的指导与验收依据。
>
> 日期：2026-04-11
> 
> 已确认关键决策（已按此作为默认方案编写）：
> - mybot 集成：保留 `mybot-main` 子项目，通过 `pip install -e mybot-main` 引入
> - Agent 工作区：使用独立 workspace（建议目录 `agent_workspace/`）
> - Agent 输出：`final_label/app/service_type/confidence/evidence/reason`（结构化 `AgentResult/v1`）

---

## 0. 术语与约定

- **PCAP**：原始抓包文件（批量离线处理）。
- **Flow（流）**：按五元组（源/目的 IP、端口、传输层协议）聚合的会话/连接记录。
- **SNI**：TLS ClientHello Server Name Indication，优先用于加密流量的“应用层”识别。
- **复合标签**：`<app>:<service_type>`。
  - `app`：应用/品牌（如 `bilibili`、`wechat`、`gmail`、`unknown_app`）。
  - `service_type`：服务类型（如 `video`、`audio`、`file`、`chat`、`news`、`control`、`web`、`email`）。
- **模块A（预处理/已知过滤）**：Zeek + nDPI（`ndpiReader`）快速过滤/标记大部分已知流量，输出已知/未知集合。
- **模块B（Agent 智能挖掘）**：基于改造的 MyBot，针对未知集合主动调用工具、多源证据融合，输出复合标签 + 解释日志 + 置信度。
- **模块C（后处理与可视化）**：统计、聚合、生成图表与审计报告。

---

## 1. 现状梳理（仓库当前真实状态）

### 1.1 仓库分区

当前仓库根目录包含两大部分：

1) **未知网络流量识别系统（业务仓库）**（根目录）：
- `config.py`：Zeek/nDPI 路径与数据目录。
- `core/preprocessing.py`：模块A主要逻辑（调用 Zeek + nDPI、生成 known/unknown）。
- `core/utils/zeek_utils.py` / `core/utils/ndpi_utils.py`：Zeek 与 nDPI 封装。
- `scripts/test_*.py`：当前主要用于单模块验证的脚本。
- `data/processed/*`：已经产出的历史 JSON/日志/CSV（注意：其 schema 与当前 `core/preprocessing.py` 版本存在分裂，见下文）。

2) **MyBot（Agent 框架）**（子项目）：
- `mybot-main/`：可安装的 Python 包 `mybot`（带 CLI + SDK）。
- 关键入口：
  - CLI：`python -m mybot` 或安装后 `mybot ...`
  - SDK：`from mybot import MyBot; bot = MyBot.from_config(...); await bot.run(...)`

### 1.2 模块A：当前实现能力与输出形态

模块A目前的目标是：**尽可能过滤 90%+ 已知流量，减少 Agent 负担**。

- Zeek：生成 `conn.log/ssl.log/http.log/dns.log/x509.log` 等。
- nDPI：`ndpiReader -i <pcap> -C <csv>` 生成流级 CSV（nDPI 5.x 下 `-C` 是“写 CSV 到指定路径”，CSV 常见分隔符为 `|`，表头可能带 `#` 前缀）。
- 结果 JSON：历史产物位于 `data/processed/results/*.json`、`data/processed/known_results/*_known.json`、`data/processed/unknown_flows/*_unknown.json`。

#### 1.2.1 Schema 分裂（需要在改造期收敛）

仓库里存在两套输出 schema：

- **历史输出（已在 `data/processed/...` 存在的 JSON）**：
  - 单条流为“扁平字段”：`flow_id/src_ip/dst_ip/sni/ndpi_app/is_encrypted/proto_stack/duration/...`。
  - `evidence` 较少，通常仅 `sni_source`。

- **当前代码意图（`core/preprocessing.py`）**：
  - 试图输出更丰富的嵌套结构（`http/dns/tls/stats/raw_sources/...`），并通过 `FlowMetadata.model_dump()` 统一序列化。

> 改造结论：需要在“整合阶段”定义并固化 **PreprocessResult v1** 与 **AgentInput v1** 两套稳定契约，并提供对历史扁平 schema 的兼容/迁移策略。

#### 1.2.2 当前发现的前置缺口（后续实现必须先修）

> 这些不是本文要改的代码，但必须在实施阶段优先处理，否则系统无法端到端联通。

- ✅ 已补齐：新增 `core/models.py`（提供 `FlowMetadata/TLSMetadata/...` 等数据模型），解除 `ImportError` 风险。
- ✅ 已补齐：在 `config.py` 增加 `CONFIDENCE_THRESHOLD` 常量，解除导入失败风险。

### 1.3 MyBot：当前能力与可扩展点

MyBot 的核心特点（适合承载模块B）：

- **事件驱动 + 多轮工具调用**：核心执行循环由 `mybot/agent/loop.py` + `mybot/agent/runner.py` 驱动。
- **Workspace 概念**：
  - 工作区根目录（`workspace`）下可放置 `AGENTS.md/SOUL.md/USER.md/TOOLS.md` 作为 bootstrap 指令。
  - 工作区下的 `skills/` 目录可放置自定义技能（每个技能一个文件夹，包含 `SKILL.md`），用于教 Agent“如何按规则调用工具”。
  - 会话（sessions）、长期记忆（memory）等也保存在 workspace 内。
- **工具系统**：默认会注册 `read_file/write_file/edit_file/list_dir/glob/grep` + `exec` + `web_search/web_fetch` 等工具。

> 改造时的关键点：为了安全与可控，需要为“未知流量识别 Agent”选择合适的 workspace 隔离策略，并明确允许/禁止的工具能力（尤其是写文件与 shell 执行）。

---

## 2. 目标整体架构（对齐 dev_doc.txt 的“两阶段架构”）

### 2.1 端到端数据流

```mermaid
flowchart LR
  PCAP[PCAP 原始文件] --> ZK[Zeek 日志]
  PCAP --> ND[nDPI CSV]
  ZK --> A[模块A 预处理/已知过滤]
  ND --> A
  A --> K[Known 集合]
  A --> U0[Unknown 集合]

  U0 --> U1[Agent 输入(精简/脱敏)]
  U1 --> B[模块B MyBot Agent]
  B --> U2[Unknown 已标注结果]

  K --> M[合并/聚合]
  U2 --> M
  M --> C[模块C 可视化/报告]
  C --> OUT[最终审计输出]
```

### 2.2 模块职责边界

- **模块A（预处理/过滤）**：只做“快速、可复现、规则化/工具化”的工作：
  - 统一流聚合 key；
  - 提取可用于后续推断的元数据（SNI/证书/HTTP Host/DNS Query/统计特征）；
  - 根据白名单与高置信规则将“已知流量”直接标记；
  - 将其余流输出为“未知集合”（并给出“为什么未知”的 reason）。

- **模块B（Agent 推断）**：只处理“模块A 未能确定”的流，特点是：
  - 结合场景（加密且 SNI 缺失/未知、明文等）选择工具链；
  - 证据融合与冲突解决（优先级：SNI > 主动获取 > 证书/IP/行为统计 > 分类模型）；
  - 输出结构化结果（复合标签、置信度、证据摘要、可追溯的工具调用线索）。

- **模块C（统计/可视化）**：不参与推断，只做：
  - 聚合比例统计；
  - 生成饼图/柱状图/Sankey 图；
  - 生成审计报告（含每条未知流推理 trace 引用）。

---

## 3. 已选整合方式（目录与运行形态）

> 目标：在不破坏 `mybot-main` 独立性的前提下，把它当作“模块B 引擎”嵌入业务系统。

### 3.1 已选方案：保留 `mybot-main` 为子项目 + 业务侧封装 Runner

**核心思想**：

- `mybot-main` 保持独立可安装；业务仓库通过 `pip install -e mybot-main` 引入。
- 业务侧新增一个“模块B 适配层”（建议放在 `core/agent/`）：
  - 负责生成 Agent 输入文件（精简/脱敏）；
  - 调用 `MyBot.from_config(...).run(...)`；
  - 解析 Agent 输出并落盘为结构化 JSON。

### 3.2 已选：引入独立的 Agent Workspace（隔离 sessions/memory/写入风险）

建议在业务仓库下引入（或运行时创建）一个独立目录，例如：

```
agent_workspace/
  AGENTS.md
  TOOLS.md
  USER.md
  SOUL.md
  skills/
  sessions/
  memory/
  inputs/
  outputs/
```

这样做的好处：

- `mybot` 的写文件工具即使误触发，也只会写到 `agent_workspace/` 内。
- 可以把 “给 LLM 的输入” 固定落在 `agent_workspace/inputs/*.json`，最大限度减少 token 与隐私泄露面。
- 可以在 `agent_workspace/` 内做 cache（例如同一 SNI 复用推断结果），降低成本。

> 运行时建议设置 mybot 的 `tools.restrict_to_workspace=true`，并把 `workspace` 指向 `agent_workspace/`。

### 3.3 备选方案（不推荐作为第一阶段）

- **直接把业务仓库根目录作为 mybot workspace**：实现快，但写入风险更高、Agent 可能读到不必要的大文件。
- **将 mybot 代码搬迁/合并进业务仓库**：后续维护成本高；建议等系统稳定后再评估。

---

## 4. 配置体系（双配置合并策略）

### 4.1 模块A配置：`config.py`（业务仓库）

当前 `config.py` 已包含：

- `ZEEK_BIN`、`NDPI_READER`：可执行文件路径（建议后续完全由环境变量覆盖，避免硬编码）。
- 数据目录：`data/processed/...` 等。

改造期建议补齐（实施阶段要做，但本文只定义）：

- `CONFIDENCE_THRESHOLD`：预处理判定阈值（建议拆为 `KNOWN_THRESHOLD` 与 `UNKNOWN_THRESHOLD` 或规则内自定义权重）。
- `AGENT_WORKSPACE_DIR`：Agent workspace 的根路径（默认 `BASE_DIR / "agent_workspace"`）。
- `MYBOT_CONFIG_PATH`：项目内 mybot config 文件路径（避免使用 `~/.mybot/config.json` 的全局状态）。

### 4.2 模块B配置：mybot `config.json`

mybot 支持通过 SDK 的 `MyBot.from_config(config_path=..., workspace=...)` 显式指定配置文件与 workspace。

推荐：把 mybot 的配置也“项目化”，例如：

- `agent_workspace/config.json` 或 `configs/mybot.config.json`（二选一即可）

关键字段建议（示例仅表达意图，字段名可用 camelCase 或 snake_case；mybot schema 支持两者）：

```json
{
  "agents": {
    "defaults": {
      "workspace": "./agent_workspace",
      "model": "github_copilot/gpt-5.2",
      "timezone": "Asia/Shanghai",
      "maxToolIterations": 30,
      "temperature": 0.1
    }
  },
  "tools": {
    "restrictToWorkspace": true,
    "web": { "enable": true },
    "exec": { "enable": false }
  }
}
```

说明：

- 第一阶段建议 **关闭 `exec`**，优先使用 `web_search/web_fetch/read_file` 等低风险工具；确需 whois/openssl 等再开启并做白名单封装。
- 若允许联网主动获取网页内容，需要在运行环境层面明确：是否允许外网访问、是否需要代理、是否需要 SSRF 白名单配置。

---

## 5. 数据与接口契约（必须先固化）

> 这是整合最关键的部分：模块A 与模块B 之间不应通过“随意 prompt 传一大坨 JSON”耦合；应有稳定的 schema + 版本号。

### 5.1 模块A输出：`PreprocessResult/v1`

建议将模块A输出统一为：

```json
{
  "schema_version": "preprocess/v1",
  "pcap_name": "email1a.pcap",
  "pcap_path": "data/sample_pcaps/email1a.pcap",
  "timestamp": "2026-04-11T10:00:00Z",
  "stats": {
    "total_flows": 2913,
    "known_count": 2768,
    "unknown_count": 145,
    "known_ratio": 95.02
  },
  "known": [ /* KnownFlow[] */ ],
  "unknown": [ /* UnknownFlow[] */ ]
}
```

#### 5.1.1 `UnknownFlow` 最小字段（Agent 必需）

建议模块A至少保证以下字段存在（否则 Agent 很难做稳定推断与聚合）：

- **关联键**：`flow_key`（稳定的 canonical key，或提供 `src/dst/ports/transport` 以便构建）
- **基础五元组**：`src_ip/src_port/dst_ip/dst_port/transport`
- **协议提示**：`ndpi_app`、`proto_stack`（或等价字段）
- **加密信息**：`is_encrypted`
- **域名信息**（可空）：`sni`、`http.host`、`dns.query`
- **统计信息**：`duration`、`c_to_s_bytes`、`s_to_c_bytes`、`total_bytes`（或统一放到 `stats` 内）
- **预处理解释**：`reason`（为什么仍然未知）

> 原则：模块A可以输出“全量结构”用于调试，但必须同时能导出“精简输入”供 Agent 使用（见 5.2）。

#### 5.1.2 `KnownFlow` 建议字段

- 至少包含 `flow_key`、`label`、`confidence`、`evidence`（例如命中白名单/系统协议/强提示等）。

### 5.2 模块B输入：`AgentInputJob/v1`（精简/脱敏）

推荐在进入 Agent 前做一次“输入整形”，把未知流从 `PreprocessResult` 转换为更适合 LLM 的结构(实际信息可能会更丰富一点)：

```json
{
  "schema_version": "agent_input/v1",
  "job": {
    "pcap_name": "email1a.pcap",
    "preprocess_result_ref": "../data/processed/results/email1a_....json",
    "timestamp": "2026-04-11T10:05:00Z",
    "policy": {
      "label_format": "<app>:<service_type>",
      "service_type_vocab": ["video","audio","file","chat","news","control","web","email"],
      "priority": ["sni","active_fetch","cert_or_ip","behavior_stats","model"],
      "offline_mode": false
    },
    "flows": [
      {
        "flow_key": "tcp:10.0.0.2:53122<->142.250.72.165:443",
        "transport": "tcp",
        "src": {"ip": "10.0.0.2", "port": 53122},
        "dst": {"ip": "142.250.72.165", "port": 443},
        "hints": {
          "is_encrypted": true,
          "sni": "smtp.googlemail.com",
          "http_host": null,
          "dns_query": null,
          "ndpi_app": "TLS",
          "proto_stack": "TLS.Google"
        },
        "stats": {"duration": 1.2, "total_bytes": 12345, "c_to_s_bytes": 2345, "s_to_c_bytes": 10000},
        "preprocess": {"reason": "加密流量 SNI 未命中白名单"}
      }
    ]
  }
}
```

建议：

- `flows[]` 内不要携带 Zeek 的 `raw_records` 之类的大块原始日志（会显著增加 token）。
- `preprocess_result_ref` 用于可追溯，而不是给 LLM 直接读全量文件。

### 5.3 模块B输出：`AgentResult/v1`

Agent 的输出必须是结构化、可机器解析、可聚合的。推荐：

```json
{
  "schema_version": "agent_result/v1",
  "pcap_name": "email1a.pcap",
  "timestamp": "2026-04-11T10:10:00Z",
  "decisions": [
    {
      "flow_key": "tcp:10.0.0.2:53122<->142.250.72.165:443",
      "final_label": "gmail:email",
      "app": "gmail",
      "service_type": "email",
      "confidence": 0.86,
      "reason": "SNI smtp.googlemail.com 命中已知邮件服务模式，且端口/行为与邮件一致",
      "evidence": [
        {"source": "sni", "value": "smtp.googlemail.com", "weight": 0.9},
        {"source": "port", "value": 443, "weight": 0.2},
        {"source": "ndpi", "value": "TLS.Google", "weight": 0.3}
      ],
      "tool_trace": {
        "session_key": "traffic:email1a:20260411",
        "notes": "如开启 web_fetch，则记录访问标题/证书摘要"
      }
    }
  ]
}
```

约束：

- `final_label` 必须能拆分为 `app` 与 `service_type`。
- `confidence` 归一化到 `[0,1]`。
- `evidence` 是“摘要”，不是全量原始日志。

### 5.4 合并输出：`FinalReport/v1`

最终输出建议包含：

- `known`（直接来自模块A）
- `unknown_labeled`（模块B 决策后的未知流）
- `aggregations`：按 app、按 service_type、按二者关系（Sankey）统计。
- `artifacts`：图表文件引用（HTML/PNG/JSON）。

---

## 6. Agent 设计（Prompt、Skills、工具与冲突解决）

### 6.1 场景划分（与 dev_doc 对齐）

Agent 必须显式区分并走不同工作流：

1) **明文流量（HTTP 或其它明文协议）**
- 优先读 `http.host/urls/content_types/user_agent` 推断。
- 必要时 `web_fetch`（访问 URL，提取标题/关键词）来判定应用与服务类型。

2) **加密流量 + SNI 存在但未知/未命中**
- 优先用 `sni` 做品牌识别（域名品牌、二级域名模式、常见 CDN/云服务区分）。
- 若允许联网：`web_search`/`web_fetch` 对域名做主动内容确认。
- 失败时：使用证书 SAN/Issuer、JA3S、IP ASN/WHOIS（若工具可用）。

3) **加密流量 + SNI 缺失（或不可得）**
- 走“证书/IP/行为统计”路径：
  - 证书 SAN/Issuer 是否暴露品牌；
  - IP ASN/归属是否指向特定云/服务；
  - 行为统计（字节方向比、持续时间、端口）推断服务类型。
- 这类流量可以允许输出 `unknown_app:<service_type>` 或 `unknown_app:web`。

### 6.2 冲突解决（优先级规则）

建议在 Agent 输出里把冲突解决逻辑显式化：

- **SNI 命中白名单或强品牌特征**：直接决定 `app`，服务类型由白名单或内容补齐。
- **主动获取成功（网页标题/关键词/可识别的站点内容）**：在 SNI 不可靠或为泛域名时可覆盖。
- **证书/JA3S/IP 归属**：中等权重证据；用于补强或在无 SNI 时兜底。
- **统计特征/分类模型**：低权重，只做辅助。

### 6.3 Skills 规划（建议清单）

建议为未知流量识别 Agent 新增 workspace skills（放在 `agent_workspace/skills/`）：

- `traffic-label-format`：输出必须是 `AgentResult/v1` JSON，禁止散文输出。
- `sni-triage`：如何从 SNI 提取品牌（泛域名识别、通配符匹配、二级域名规则）。
- `web-title-extract`：如何用 `web_fetch` 访问域名/URL，抽取标题与关键词，判断 `app/service_type`。
- `cert-summary`：如何从 TLS 元数据（SAN/Issuer/JA3S）提取有用线索（不要求实现 openssl）。
- `ip-intel`（可选，若后续开放 exec）：如何使用 `whois`/`ipinfo` 类工具判断 ASN/归属。

每个 skill 都应包含：

- 触发条件（何时使用）
- 输入字段（从 AgentInputJob 读哪些字段）
- 工具使用步骤
- 失败回退策略
- 输出字段映射（如何写入 `evidence`）

### 6.4 工具能力与安全策略（建议默认最小权限）

- 建议默认：
  - 允许：`read_file`（读取 `inputs/*.json`）、`web_search/web_fetch`（若允许联网）、`list_dir`。
  - 禁止或谨慎开启：`write_file/edit_file`（避免污染数据）、`exec`（避免误操作与环境差异）。
- 若必须开启 `exec`：
  - 建议只允许在 `agent_workspace/` 下工作；
  - 并用技能明确“可执行命令白名单”（例如只允许 `whois`, `openssl x509`, `curl -I` 等只读命令）。

---

## 7. 端到端运行流程（实现阶段的建议入口）

> 下面描述的是“实现后”的推荐流程，用于指导后续写脚本/模块。

### 7.1 单 PCAP（离线）流程

1. 模块A运行：
- 输入：PCAP 路径
- 输出：`PreprocessResult/v1` + `known/unknown` 拆分文件 + Zeek/nDPI 中间产物

2. 生成 Agent 输入：
- 从 `unknown[]` 精简生成 `AgentInputJob/v1`，写入 `agent_workspace/inputs/<pcap>_<ts>.json`

3. 模块B运行（MyBot SDK）：
- `workspace=agent_workspace/`
- prompt：要求读取输入文件并输出 `AgentResult/v1` JSON

4. 合并：
- 将模块B `decisions[]` 以 `flow_key` 回填到 unknown flows
- 生成 `FinalReport/v1`

5. 可视化：
- 生成饼图/柱状图/Sankey 图
- 输出到 `data/results/` 或 `data/processed/results/` 的指定目录

### 7.2 批量 PCAP 流程（目录输入）

- 遍历 PCAP 列表。
- 每个 PCAP 独立产出一份 `FinalReport/v1`。
- 额外提供一个“全局汇总”报告：合并多 PCAP 的统计结果。

### 7.3 性能与成本控制（建议）

- Agent 输入分块：每次只喂给 LLM N 条流（例如 10~30 条），防止上下文爆炸。
- 缓存：对相同 `sni` 或相同 `dst_ip` 的结论做缓存（写入 `agent_workspace/outputs/cache.json`），避免重复搜索。
- 并发：mybot 支持会话级并发门限（环境变量 `MYBOT_MAX_CONCURRENT_REQUESTS`），可在批处理时适度开启并发。

---

## 8. 日志、可观测性与评估

### 8.1 日志落盘建议

- 模块A：保留 Zeek 日志目录与 nDPI CSV（便于溯源）。
- 模块B：
  - 以 `session_key` 绑定一次 PCAP 处理（例如 `traffic:<pcap_stem>:<ts>`）。
  - 让 mybot sessions 保存每轮工具调用（天然具备 trace）。
  - 额外把 Agent 的最终 JSON 输出单独落盘（不要只存在对话里）。

### 8.2 评估与 LangSmith（规划）

dev_doc.txt 中提到“集成 LangSmith 进行 Agent 调试与评估”。实现阶段建议路径：

- 用 mybot 的 Hook 机制（`AgentHook`）在“模型调用前后/工具调用前后”记录事件。
- 将事件导出到：
  - 本地 JSONL（最低成本，先做这个），或
  - LangSmith/其它 tracing 平台（第二阶段再接）。

---

## 9. 改造步骤与里程碑（建议按本科周期切分）

### Phase 0：环境与依赖收敛（1~2 天）

- 明确 Python 版本（建议 3.10+）。
- 建立统一 venv。
- 通过 `pip install -e mybot-main` 让业务侧可 import `mybot`。

### Phase 1：模块A可运行与 schema 固化（2~4 天）

- 补齐 `core/models.py`（Pydantic v2）并与 `core/preprocessing.py` 对齐。
- 在 `config.py` 补齐缺失常量（至少 `CONFIDENCE_THRESHOLD`）。
- 产出 `PreprocessResult/v1` 并提供“兼容历史扁平输出”的转换脚本（只读迁移）。

### Phase 2：模块B最小闭环（3~6 天）

- 创建 `agent_workspace/` 初始化模板与 skills（只要能让 Agent 输出严格 JSON）。
- 实现 `core/agent/runner.py`：
  - 读取 `AgentInputJob/v1`
  - 调用 mybot SDK
  - 解析与校验输出 JSON
  - 落盘 `AgentResult/v1`

### Phase 3：合并与可视化（2~5 天）

- 合并 known + unknown_labeled。
- 实现最小可视化：
  - 应用层占比饼图
  - 服务类型柱状图
  - Sankey（应用→服务类型）

### Phase 4：证据增强与主动工具迭代（持续迭代）

- 开启/封装 IP 归属/WHOIS/证书细节工具。
- 引入低权重分类模型工具（可选）。
- 冲突案例收集与规则/提示词微调。

---

## 10. 已确认决策（实现阶段按此执行）

1) **mybot 的集成方式**：保留 `mybot-main` 子项目，并通过 `pip install -e mybot-main` 引入；业务侧以 SDK 方式调用（`MyBot.from_config(...).run(...)`）为主。

2) **Agent workspace 放置**：使用独立目录 `agent_workspace/` 作为 mybot workspace，并默认开启 `tools.restrict_to_workspace=true` 以隔离 sessions/memory/写入风险。

3) **Agent 输出的严格程度**：模块B输出采用结构化 `AgentResult/v1`，每条决策至少包含 `final_label/app/service_type/confidence/evidence/reason`（便于论文实验、可视化与审计溯源）。

---

## 11. 附录：历史输出（扁平 schema）兼容提示

仓库现有 `data/processed/unknown_flows/*_unknown.json` 的流对象大致为：

```json
{
  "flow_id": 349,
  "src_ip": "fe80::...",
  "dst_ip": "ff02::...",
  "sni": null,
  "ndpi_app": "ICMPV6",
  "is_encrypted": true,
  "proto_stack": "ICMPV6",
  "duration": 495.637,
  "c_to_s_bytes": 430,
  "s_to_c_bytes": 0,
  "total_bytes": 430,
  "confidence": 0.4,
  "evidence": {"sni_source": "none"},
  "reason": "SNI未知或不在白名单"
}
```

实现阶段如需兼容：

- 可在“Agent 输入整形”时补齐：`flow_key`、`src_port/dst_port/transport`（若历史文件缺失，则需要从 nDPI CSV 或 Zeek conn.log 回查）。

---
