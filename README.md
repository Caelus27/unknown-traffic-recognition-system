# 未知网络流量应用协议识别系统

校园网真实流量审计系统：先用 Zeek + nDPI 过滤已知流量，对剩余未知流量切片成单流 PCAP 交给 ET-BERT 端到端分类模型预判，再由 LLM Agent 主动多工具分析得到复合标签 `<app>:<service_type>`，最后聚合可视化。

## 架构概览

```
PCAP --> [模块A: Zeek + nDPI + 未知流切片 + ET-BERT 回填]
              |
              +--> known/ + unknown/ + unknown_flows_pcap/<task_id>/
                                                     |
                                                     v
              +--> [模块B: mybot Agent 推断未知流]
                                                     |
                                                     v
              +--> [模块C: 合并 + Plotly 可视化] --> FinalReport/v1
```

## 目录结构（核心）

```
unknown-traffic-recognition-system/
├── config.py                       # 全局路径与开关（Zeek/nDPI/分类模型/Agent 工作区）
├── core/
│   ├── preprocessing.py            # 模块A 主体
│   ├── models.py                   # Pydantic 数据模型
│   ├── classifier/
│   │   ├── adapter.py              # 分类模型动态加载框架（module:function）
│   │   └── etbert_adapter.py       # 默认接入 classifier_model 的真实适配器
│   ├── agent/
│   │   ├── runner.py               # 包装 mybot SDK
│   │   ├── input_builder.py        # PreprocessResult/v1 -> AgentInputJob/v1
│   │   ├── result_parser.py        # outputs/*.json -> AgentResult/v1
│   │   └── schema.py               # 数据契约
│   ├── merge.py                    # 合并产 FinalReport/v1
│   └── visualization.py            # Plotly 三图（饼/柱/Sankey）
├── classifier_model/               # 独立 ET-BERT 推理子模块（自带 README）
├── mybot-main/                     # 独立的 mybot Agent 框架
├── agent_workspace/                # Agent 工作区（AGENTS.md / TOOLS.md / SOUL.md / USER.md / config.json / skills/）
├── data/
│   ├── sample_pcaps/
│   ├── known_sni_list.json
│   ├── processed/                  # 模块A 中间产物
│   └── results/                    # FinalReport/v1 与可视化 HTML
└── scripts/run_pipeline.py         # 端到端入口
```

## 安装

```bash
# 1. Python 依赖
pip install -e mybot-main         # mybot agent 框架
pip install plotly                # 可视化（缺失时流水线降级跳过）
pip install pydantic pandas       # 模块A 已有依赖
pip install torch scapy           # 仅在启用 ET-BERT 分类模型时需要
pip install pytest                # 仅运行测试时需要
```

外部工具（链外，需要自行安装）：
- **Zeek**：默认路径 `/opt/zeek/bin/zeek`，可通过环境变量 `ZEEK_BIN` 覆盖。
- **nDPI**（`ndpiReader`）：默认路径见 `config.py`，可通过 `NDPI_READER` 覆盖。
- **ET-BERT 模型权重**：放到 `classifier_model/models/best_model.bin` 与 `encryptd_vocab.txt`，或通过 `CLASSIFIER_MODEL_BIN` / `CLASSIFIER_VOCAB` 覆盖路径。

## 配置

### 1. 模块A / 分类模型开关

```bash
# 启用 ET-BERT 端到端分类模型（缺省关闭）
export CLASSIFIER_ENABLE=true
export CLASSIFIER_ADAPTER="core.classifier.etbert_adapter:run_etbert_classifier"
export CLASSIFIER_MODEL_NAME="etbert_v1"
# 可选覆盖：
# export CLASSIFIER_MODEL_BIN=/abs/path/to/best_model.bin
# export CLASSIFIER_VOCAB=/abs/path/to/encryptd_vocab.txt
```

### 2. mybot Agent / LLM 配置

仓库自带 `agent_workspace/config.json`（占位配置），**不含 api_key**。两种填法二选一：

- **方式 A — 环境变量（推荐）**：mybot 支持 `${ENV_VAR}` 占位符。在 `~/.mybot/config.json` 或 shell 中导出：
  ```bash
  export OPENROUTER_API_KEY=sk-...
  ```
  然后修改 `agent_workspace/config.json` 增加：
  ```json
  "providers": { "openrouter": { "api_key": "${OPENROUTER_API_KEY}" } }
  ```
- **方式 B — 用 mybot 默认全局配置**：在 `~/.mybot/config.json` 配好 provider 与 api_key，启动时把 `MYBOT_CONFIG_PATH` 指向它：
  ```bash
  export MYBOT_CONFIG_PATH=~/.mybot/config.json
  ```

`agent_workspace/config.json` 默认 `model = openrouter/openai/gpt-4o-mini`，按需替换为 `anthropic/claude-opus-4-5` 或 `deepseek/deepseek-chat` 等。

## 运行

### 完整流水线
```bash
python scripts/run_pipeline.py data/sample_pcaps/email1a.pcap
```

产物：
- `data/processed/results/<task_id>.json` — 预处理 JSON（PreprocessResult/v1）
- `data/processed/unknown_flows_pcap/<task_id>/` — 单流 PCAP + manifest
- `agent_workspace/inputs/*.json`、`agent_workspace/outputs/*.json` — Agent 中间产物
- `data/results/<task_id>/final_report.json` — 最终合并产物（FinalReport/v1）
- `data/results/<task_id>/{app_pie,service_type_bar,app_service_sankey}.html` — 三张可视化图表

### 降级跑法
```bash
# 不启用 LLM、不出可视化（只走模块A，本地零依赖）
python scripts/run_pipeline.py data/sample_pcaps/email1a.pcap --no-agent --no-viz

# 限制 Agent 单批 flow 数（控制 LLM 上下文）
python scripts/run_pipeline.py data/sample_pcaps/email1a.pcap --max-flows-per-chunk 10
```

### 仅跑模块A（保留旧入口）
```bash
python scripts/test_preprocessing.py data/sample_pcaps/email1a.pcap
```

## 测试

```bash
pytest tests/ -q
```

仅覆盖关键集成点（`core/agent/result_parser.py`、`core/merge.py`）；端到端测试通过运行 `scripts/run_pipeline.py` 对 `data/sample_pcaps/` 下的样例 PCAP 来验证。

## 数据契约（schema 速查）

- **PreprocessResult/v1**（模块A 输出）：见 `core/preprocessing.py:160`
- **AgentInputJob/v1** / **AgentResult/v1**：见 `core/agent/schema.py`
- **FinalReport/v1**：见 `core/merge.py:build_final_report`
- 详细字段说明对齐 `integration_dev_doc.md` 第 5 节。

## 已知问题与边界

- 流水线本次只走通**单 PCAP**；批量处理建议外层用 shell for 循环。
- Agent prompt 第一轮可能因 LLM 输出 schema 偏差被 `result_parser` 丢弃 service_type；可通过 `agent_workspace/skills/traffic_classify/SKILL.md` 调优。
- ET-BERT 模型权重未随仓库分发，需要单独获取后放到 `classifier_model/models/`。
- Agent web_fetch 能否成功取决于运行环境是否能直连外网（参见 `mybot-main/SECURITY.md`）。
