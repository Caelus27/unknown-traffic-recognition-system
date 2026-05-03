# 未知网络流量应用协议识别系统 × MyBot 整合改造开发文档（设计稿）

> 目的：把当前仓库中的三部分代码（“未知网络流量应用协议识别系统”框架 + `mybot-main`+classifier_model）整合为一个可端到端运行的离线批处理系统。
> 
> 已确认关键决策（已按此作为默认方案编写）：
> - mybot 集成：保留 `mybot-main` 子项目独立性，在业务侧封装调用。
> - Agent 工作区：使用独立 workspace（建议目录 `agent_workspace/`）
> - Agent 输出：`final_label/app/service_type/confidence/evidence/reason`（结构化 `AgentResult/v1`）
> - 分类模型边界：分类模型作为模块A预处理阶段的可插拔步骤，不作为 Agent 工具；模型结果随未知流 JSON 一起交付给 Agent
> - 未知流 PCAP 产物：每次预处理任务在 `data/processed/unknown_flows_pcap/<task_id>/` 下生成独立目录，供后续端到端分类模型按 PCAP 输入分析
---

## 0. 术语与约定

- **PCAP**：原始抓包文件（批量离线处理）。
- **Flow（流）**：按五元组（源/目的 IP、端口、传输层协议）聚合的会话/连接记录。
- **SNI**：TLS ClientHello Server Name Indication，优先用于加密流量的“应用层”识别。
- **复合标签**：`<app>:<service_type>`。
  - `app`：应用/品牌（如 `bilibili`、`wechat`、`gmail`、`unknown_app`，主要由agent负责识别）。
  - `service_type`：服务类型（固定为0: "bulk-transfer",1: "interactive",2: "stream",3: "vpn",4: "web"中的一个，这几类和分类模型能对应，agent根据模型输出和其他证据进行判断）。
- **模块A（预处理/已知过滤/分类模型接口）**：Zeek + nDPI（`ndpiReader`）快速过滤/标记大部分已知流量，输出已知/未知集合；同时把未知流从原始 PCAP 中切分为新的 PCAP 产物，并预留分类模型输出字段。
- **模块B（Agent 智能挖掘）**：基于改造的 MyBot，针对未知集合主动调用工具、多源证据融合，输出复合标签 + 解释日志 + 置信度。
- **模块C（后处理与可视化）**：统计、聚合、生成图表与审计报告。

---

## 1. 现状梳理（仓库当前真实状态）

### 1.1 仓库分区

当前仓库根目录包含三大部分：

1) **未知网络流量识别系统（业务仓库）**（根目录）：
- `config.py`：Zeek/nDPI 路径与数据目录。
- `core/preprocessing.py`：模块A主要逻辑（调用 Zeek + nDPI、生成 known/unknown；后续需补未知流 PCAP 切分与分类模型接口）。
- `core/utils/zeek_utils.py` / `core/utils/ndpi_utils.py`：Zeek 与 nDPI 封装。
- `scripts/test_*.py`：当前主要用于单模块验证的脚本。
- `data/processed/*`：已经产出的历史 JSON/日志/CSV（注意：其 schema 与当前 `core/preprocessing.py` 版本存在分裂，见下文）。

2) **MyBot（Agent 框架）**（子项目）：
- `mybot-main/`：可安装的 Python 包 `mybot`（带 CLI + SDK）。
- 关键入口：
  - CLI：`python -m mybot` 或安装后 `mybot ...`
  - SDK：`from mybot import MyBot; bot = MyBot.from_config(...); await bot.run(...)`

3） **分类模型（classifier_model）**:具体见 `classifier_model/README.md`，是一个完全独立的模块，当前实现了从 PCAP 生成推理数据和加载模型推理的功能；后续改造时会作为模块A内部可插拔组件，提供分类结果回填到未知流 JSON 的接口。

### 1.2 模块A：输出形态

模块A的目标是：**尽可能过滤 90%+ 已知流量，减少 Agent 负担**。

- Zeek：生成 `conn.log/ssl.log/http.log/dns.log/x509.log` 等。
- nDPI：`ndpiReader -i <pcap> -C <csv>` 生成流级 CSV（nDPI 5.x 下 `-C` 是“写 CSV 到指定路径”，CSV 常见分隔符为 `|`，表头可能带 `#` 前缀）。
- 结果 JSON：历史产物位于 `data/processed/results/*.json`、`data/processed/known_results/*_known.json`、`data/processed/unknown_flows/*_unknown.json`。
- 未知流 PCAP：在 `data/processed/unknown_flows_pcap/<task_id>/` 下为每次任务生成目录，保存未知流对应的 PCAP 文件与 manifest。


#### 1.2.1 当前发现的前置缺口（后续实现必须先修）

> 这些不是本文要改的代码，但必须在实施阶段优先处理，否则系统无法端到端联通。

- ❌ 当前未补齐：`core/preprocessing.py` 导入了 `core.models`，但仓库中未发现 `core/models.py`；实施阶段必须先补齐 `FlowMetadata/TLSMetadata/...` 等数据模型，否则预处理脚本会导入失败。
- ✅ 已补齐：在 `config.py` 增加 `CONFIDENCE_THRESHOLD` 常量，解除该常量导入失败风险。

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
  A --> U0[Unknown 元数据集合]
  A --> UP[未知流 PCAP 任务目录]
  UP --> CM[分类模型(预处理插件)]
  CM --> U0

  U0 --> U1[Agent 输入]
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
  - 将其余流输出为“未知集合”（并给出“为什么未知”的 reason）；
  - 从原始 PCAP 中切分未知流对应的流量包，按任务生成 `unknown_flows_pcap/<task_id>/` 目录；
  - 预留并调用分类模型接口：模型依次读取本次任务的未知流 PCAP，返回标签与概率，再回填到未知流 JSON；模型未接入时字段保持空值。

- **模块B（Agent 推断）**：只处理“模块A 未能确定”的流，特点是：
  - 结合场景（加密且 SNI 缺失/未知、明文等）选择工具链；
  - 证据融合与冲突解决（优先级：SNI > 主动获取 > 证书/IP/行为统计 > 分类模型预处理结果）；
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
- `UNKNOWN_FLOWS_PCAP_DIR`：未知流 PCAP 输出根目录，默认 `PROCESSED_DIR / "unknown_flows_pcap"`。
- `CLASSIFIER_ENABLE` / `CLASSIFIER_MODEL_NAME`：分类模型是否接入与模型标识；未接入时默认关闭。
- `CLASSIFIER_INPUT_MODE`：建议先约定为 `per_flow_pcap`，即每个未知流对应一个 PCAP 文件；如后续模型只支持“本次任务全部未知流一个 PCAP”，需在 manifest 中明确 flow 对应关系。
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
  "artifacts": {
    "unknown_flows_pcap_dir": "data/processed/unknown_flows_pcap/email1a_20260411_100000",
    "unknown_flows_manifest": "data/processed/unknown_flows_pcap/email1a_20260411_100000/manifest.json"
  },
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
- **未知流 PCAP 引用**：`unknown_pcap_path`（指向 `unknown_flows_pcap/<task_id>/` 下的单流 PCAP；无法切分时可为 `null`，但必须在 `pcap_extraction.status` 中说明）
- **分类模型结果**：`classification_model.label`、`classification_model.probability`（模型未接入或未运行时为 `null`），以及 `classification_model.status`

> 原则：模块A可以输出“全量结构”用于调试，但必须同时能导出“精简输入”供 Agent 使用（见 5.2）。

#### 5.1.2 `KnownFlow` 建议字段

- 至少包含 `flow_key`、`label`、`confidence`、`evidence`（例如命中白名单/系统协议/强提示等）。

#### 5.1.3 未知流 PCAP 与分类模型接口

每次调用 `process_pcap()` 都应生成一个稳定任务 ID（建议 `<pcap_stem>_<timestamp>`），并在 `data/processed/unknown_flows_pcap/<task_id>/` 下写入：

- `manifest.json`：记录原始 PCAP、任务时间、每条 unknown flow 的 `flow_key`、五元组、`unknown_pcap_path`、切分状态。
- `flow_000001.pcap`、`flow_000002.pcap`...：建议每个未知流一个 PCAP 文件，便于端到端 PCAP-标签模型逐个读取；如果后续模型要求批量 PCAP，也可以额外生成 `all_unknown_flows.pcap`，但不能替代 manifest。

分类模型作为模块A内部可插拔接口，推荐约定如下输入输出：

```json
{
  "input": {
    "task_id": "email1a_20260411_100000",
    "unknown_flows_pcap_dir": "data/processed/unknown_flows_pcap/email1a_20260411_100000",
    "manifest_path": "data/processed/unknown_flows_pcap/email1a_20260411_100000/manifest.json"
  },
  "output": [
    {
      "flow_key": "tcp:10.0.0.2:53122<->142.250.72.165:443",
      "pcap_path": "data/processed/unknown_flows_pcap/email1a_20260411_100000/flow_000001.pcap",
      "label": "gmail:email",
      "probability": 0.72,
      "model_name": "pending_classifier",
      "topk": []
    }
  ]
}
```

在模型代码尚未嵌入系统前，UnknownFlow 仍然必须包含占位字段：

```json
{
  "unknown_pcap_path": "data/processed/unknown_flows_pcap/email1a_20260411_100000/flow_000001.pcap",
  "pcap_extraction": {"status": "ok", "error": null},
  "classification_model": {
    "status": "not_run",
    "model_name": null,
    "label": null,
    "probability": null,
    "topk": [],
    "error": null
  }
}
```

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
      "priority": ["sni","active_fetch","cert_or_ip","behavior_stats","classification_model"],
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
          "proto_stack": "TLS.Google",
          "classification_model": {
            "status": "not_run",
            "label": null,
            "probability": null,
            "model_name": null
          }
        },
        "artifacts": {
          "unknown_pcap_path": "data/processed/unknown_flows_pcap/email1a_20260411_100000/flow_000001.pcap"
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
- `classification_model` 只携带模型判断摘要（标签、概率、状态、模型名），Agent 不直接读取或调用分类模型代码。
- `unknown_pcap_path` 用于追溯和审计，不建议默认让 Agent 读取二进制 PCAP。

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
        {"source": "ndpi", "value": "TLS.Google", "weight": 0.3},
        {"source": "classification_model", "value": null, "weight": 0.1}
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


## 6. 端到端运行流程（实现阶段的建议入口）

> 下面描述的是“实现后”的推荐流程，用于指导后续写脚本/模块。

### 7.1 单 PCAP（离线）流程

1. 模块A运行：
- 输入：PCAP 路径
- 输出：`PreprocessResult/v1` + `known/unknown` 拆分文件 + Zeek/nDPI 中间产物 + `unknown_flows_pcap/<task_id>/` 任务目录

2. 未知流 PCAP 切分与分类模型接口：
- 根据 unknown flows 的五元组/时间范围，从原始 PCAP 中切出对应包，生成单流 PCAP 与 `manifest.json`
- 若分类模型已接入：模型依次读取本次任务目录下的 unknown flow PCAP，返回 `label/probability/topk`
- 若分类模型未接入：保留 `classification_model.status="not_run"`，`label/probability=null`

3. 生成 Agent 输入：
- 从 `unknown[]` 精简生成 `AgentInputJob/v1`，写入 `agent_workspace/inputs/<pcap>_<ts>.json`

4. 模块B运行（MyBot SDK）：
- `workspace=agent_workspace/`
- prompt：要求读取输入文件并输出 `AgentResult/v1` JSON

5. 合并：
- 将模块B `decisions[]` 以 `flow_key` 回填到 unknown flows
- 生成 `FinalReport/v1`

6. 可视化：
- 生成饼图/柱状图/Sankey 图
- 输出到 `data/results/` 或 `data/processed/results/` 的指定目录


### 7.2 性能与成本控制（建议）

- Agent 输入分块：每次只喂给 LLM N 条流（例如 10~30 条），防止上下文爆炸。
- 缓存：对相同 `sni` 或相同 `dst_ip` 的结论做缓存（写入 `agent_workspace/outputs/cache.json`），避免重复搜索。
- 并发：mybot 支持会话级并发门限（环境变量 `MYBOT_MAX_CONCURRENT_REQUESTS`），可在批处理时适度开启并发。

---

注意，目前只需要走通流程，能从 PCAP 产出预处理结果、生成 Agent 输入、得到 Agent 输出，并完成回填与报告生成；后续可以逐步优化每个模块的细节与性能。

