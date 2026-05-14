&#x20;---

&#x20; 1. 工具路由作为优化面：技能文档 + Prompt 里把"工具肖像"画清楚



&#x20; 思想：在 LLM Agent 的能力工程里，"已注册" ≠ "会被使用"。模型默认走最显眼的通用路径（如

&#x20; web\_search），即使更专的工具（mcp\_ip2location）已经在工具列表里。工具的可用性必须以"工具路由表"的形式出现在 system

&#x20; prompt + skill doc 里，否则就是高昂的"已存在但失活"的工具。



&#x20; 举措：

&#x20; - 在 agent\_workspace/AGENTS.md / TOOLS.md / skills/traffic\_classify/SKILL.md

&#x20; 中写一张二维表（任务×首选工具×禁用工具），列举每个 MCP 服务（ip2location / firecrawl）的使用前提与示例参数

&#x20; - 把同一张表内嵌到 core/agent/runner.py:\_PROMPT\_TEMPLATE 顶部——保证即使 LLM 不读 docs 也能在 system prompt 看到

&#x20; - 用日志做实证（recent.log）：每个工具的调用次数 + 调用间时延 → 量化路由失败的成本



&#x20; 量化：跑一次 18 flow / 单 chunk 改进前后的工具时延：



&#x20; ┌────────────────────┬────────────────┬─────────────────┐

&#x20; │        工具        │      改前      │    改后预估     │

&#x20; ├────────────────────┼────────────────┼─────────────────┤

&#x20; │ web\_search         │ 17 次 / 335 s  │ 0 / 0 s         │

&#x20; ├────────────────────┼────────────────┼─────────────────┤

&#x20; │ exec               │ 24 次 / 195 s  │ 0 / 0 s         │

&#x20; ├────────────────────┼────────────────┼─────────────────┤

&#x20; │ read\_file 分页     │ 27 次 / 177 s  │ 1-2 次 / \~10 s  │

&#x20; ├────────────────────┼────────────────┼─────────────────┤

&#x20; │ mcp\_ip2location    │ 1 次（参数错） │ \~6 次 / 30-60 s │

&#x20; ├────────────────────┼────────────────┼─────────────────┤

&#x20; │ 单 chunk wall time │ \~14 min        │ 预计 2-3 min    │

&#x20; └────────────────────┴────────────────┴─────────────────┘



&#x20; 论文角度：可以提出 "Tool Affordance Curation" 这个观点——LLM Agent 系统的性能瓶颈常常不在模型本身，而在 prompt 与 skill

&#x20;  文档对工具集的"曝光质量"。可以与 ReAct / Toolformer

&#x20; 的"工具学习"路线对照：那些方法靠训练让模型学会工具，本工作展示出通过 prompt curation

&#x20; 即可在已有模型上获得数量级的工具效率提升，并给出可复用的工程模式。



&#x20; ---

&#x20; 2. 输入预过滤：信息论意义上的"无证据 flow"不喂 LLM



&#x20; 思想：把"未知流量"切成两类——有任意识别信号的（agentable）和完全无信号的（doomed）。后者送 LLM 也只能返回 null，纯粹是

&#x20; token 浪费。可识别信号：SNI / TLS SAN / HTTP host / DNS query / ET-BERT prob ≥ τ / 非泛型 nDPI / 充分字节数。



&#x20; 举措：core/agent/runner.py:\_is\_agentable() + \_partition\_agentable()，在送 build\_agent\_input 之前就把 doomed flow

&#x20; 抠出来，合成带具体原因（"pre-filtered: 无 SNI; 无 HTTP host; 无 DNS query; 分类模型无输出; total\_bytes=121"）的 null

&#x20; decision；merge 阶段保留这些 reason 而非笼统覆盖成 "agent\_skipped"。



&#x20; 量化：真实数据 37 条未知流 → agentable=18 / doomed=19，LLM 输入量减半，无任何质量损失（doomed 即便送 LLM 也是

&#x20; null）。chunk 数 2 → 1，串行时间也减半。



&#x20; 论文角度：这是经典的 "dispatch / triage 模式" 在 LLM

&#x20; 流水线里的应用。可以从信息论角度论证：当一条流量样本的所有可识别特征向量都落在"无信息"分布中，LLM 推理的期望信息增益为

&#x20;  0，应跳过。可与 RAG 里的 "irrelevant chunk filtering" 类比，但目标是降低 LLM 调用次数而非检索精度。



&#x20; ---

&#x20; 3. 多门防御性工具调用预算



&#x20; 思想：在 LLM Agent 框架里把"工具调用资源"建模为可计量的预算资源，用三层正交门把住调用：(a) 防同一调用复读，(b)

&#x20; 防同一目标多工具同时穷举，(c) 防类型错配（如 IP 喂给 domain-only 工具）。每次拒绝都把合成 Error: … 作为 tool result

&#x20; 回灌给 LLM，让模型在同一轨迹内修正。



&#x20; 举措（mybot-main/mybot/utils/runtime.py）：

&#x20; - \_MAX\_REPEAT\_EXTERNAL\_LOOKUPS=2：相同 (tool, arg) 复读 ≤ 2

&#x20; - \_MAX\_PER\_TARGET\_LOOKUPS=2：跨 web\_fetch/web\_search/whois/dns\_\*/mcp\_firecrawl\_\*/mcp\_ip2location\_\* 对同一 target 合计

&#x20; ≤ 2

&#x20; - \_DOMAIN\_ONLY\_TOOLS 收到 IP 字面量直接拒，附建议替代方案

&#x20; - ip2location 的 ip 参数必须是合法单 IP（拒绝 "1.1.1.1, 2.2.2.2" 这类逗号串）



&#x20; 量化：在原始 14 min run 里，超过 6 min 是各种"对同一 IP 反复用不同工具试错"，新预算让这类调用最多发生 2 次后被截断。



&#x20; 论文角度：Agent 安全 / 经济性研究里的"runtime guardrails"。和 prompt-only 约束相比，runtime 强制 + 反馈式 Error

&#x20; 的双重作用更有效——LLM 看到 Error: per-target budget exhausted ... move on 之后会立即转向下一条

&#x20; flow。可以画一张状态机图：tool call → gate → (passed | synthetic error → LLM observes → next iteration)。



&#x20; ---

&#x20; 4. 混合证据融合：确定性分类器在 LLM 失声时兜底



&#x20; 思想：LLM 在证据稀疏时倾向给 null（保守），但流水线里已经有 ET-BERT 的高置信度概率输出可用。用 LLM 做"高语义判断"，用

&#x20; deterministic 模型做"低置信度兜底"，两者通过置信度衰减系数（这里取 0.6）融合，避免兜底过度自信。



&#x20; 举措（core/agent/runner.py:\_apply\_classifier\_fallback）：解析完 LLM 输出后扫描所有 final\_label=null 的

&#x20; decision，若对应 flow 的 classification\_model.probability ≥ 0.5，合成 "unknown:<service\_type>"（注意 app="unknown"

&#x20; 表达"协议层未知"），confidence = cm\_prob × 0.6，并在 evidence 里附 source: classification\_model。



&#x20; 量化：真实数据上覆盖率从 8/37 (21.6%) → 15/37 (40.5%)，未碰 LLM 一根毫毛。



&#x20; 论文角度：LLM + 经典分类器的 late-fusion 模式，针对异构置信度的对齐问题（LLM

&#x20; 的"我不会"与分类器的"概率分布"不可比）。提出"confidence deflation" 因子作为对齐策略，并在 evidence

&#x20; 链里保留来源标记，方便下游审计。



&#x20; ---

&#x20; 5. LLM 输出的鲁棒摄入：宽容解析 + flow\_key 白名单



&#x20; 思想：LLM 输出的 JSON 经常带 // 注释、markdown 围栏、占位符、多余前后缀；同时会幻觉出输入里没有的 ID。"严格 JSON

&#x20; parser + 全盘信任 LLM" 是数据丢失的最大单点。把解析层做成"渐进降级"，把白名单写成"硬过滤"。



&#x20; 举措（core/agent/result\_parser.py）：

&#x20; - 解析 fallback 链：json.loads → 去 markdown 围栏 → 去 // 与 /\* \*/ → 去末尾逗号 → 截取最外层 {...}，每一级都记录

&#x20; recovery note 进 errors\[]

&#x20; - 调用方传入 valid\_flow\_keys（由 chunk 输入预读获得），任何 flow\_key 不在白名单的 decision 直接丢弃并记入 errors



&#x20; 量化（recent 一次失败 run）：从 chunk\_01 一个被 // 其他 24 条决策将在这里添加 损坏的文件里抢救出 1 条有效 decision；从

&#x20;  chunk\_02 中剔除 11 条幻觉 flow\_key——之前这些都会被静默丢弃或污染最终结果。



&#x20; 论文角度：和数据库领域的 "lenient ingestion + audit log" 模式同构。对于"自然语言输出 →

&#x20; 结构化数据"的接口，提出"宽容解析 + 来源验证 + 错误可观测"三件套是必要的。



&#x20; ---

&#x20; 6. 异步 chunk 并行 + 单进程并发上限



&#x20; 思想：LLM 调用属于 IO bound（等远端响应），多个 chunk 的会话独立，理论上完全可以并行。但 provider 有 rate limit → 用

&#x20; asyncio.Semaphore(N) 设上限，既拿到并行收益又不触发 429。



&#x20; 举措（core/agent/runner.py）：把原来的 for input\_path in input\_paths: await bot.run(...) 串行循环改写为

&#x20; asyncio.gather(\*coros) + Semaphore(\_DEFAULT\_CHUNK\_CONCURRENCY=3)，并提供 AGENT\_CHUNK\_CONCURRENCY 环境变量覆盖。



&#x20; 量化：mock 测试 3 chunk × 1 s LLM → 串行 3.0 s，并行(3) 1.0 s。



&#x20; 论文角度：偏工程，但论文里可写一句：LLM Agent 系统里 chunk 间的 idempotency（彼此不依赖）让 chunk-level

&#x20; 并行成为"零成本"加速点；与 "speculative decoding" 这种模型层的并行互补。



&#x20; ---

&#x20; 7. 全程可解释：把 Agent 推理 trace 摆到 Dashboard 里



&#x20; 思想：未知流量识别系统的输出对运维有"取证价值"，必须能回答 "为什么这条流被标成 X"。LLM 的推理过程（每轮回答 / 思考链 /

&#x20;  工具调用）是天然的解释来源，只要能把 session 文件 ↔ 任务 ↔ flow 关联起来就能直接展示。



&#x20; 举措：

&#x20; - web/tasks.py 在跑 Agent 之前 / 之后对 agent\_workspace/sessions/ 做目录快照（snapshot diff），把本任务新写入的

&#x20; \*.jsonl 路径记到 task 元数据里——避免靠文件名匹配（脆弱）

&#x20; - web/reporting.py:load\_agent\_trace 解析 jsonl 区分 metadata 与 messages，并对超大 trace 加 5MB 截断防卫

&#x20; - 前端 Modal 三 Tab：「概要」（reason / evidence / tool\_trace）、「流特征」（五元组 / TLS / DNS / 字节统计 /

&#x20; 模型预判）、「Agent 推理」（按 role 上色的时间轴，可展开 reasoning\_content 与 tool\_calls）



&#x20; 论文角度：Agentic 系统的 interpretability via provenance 范式。和 "explainable ML" 不同的是，LLM Agent

&#x20; 的解释不是后构建的，而是过程产物——只需正确的存储与索引就能呈现。可以提"session snapshot diffing"作为一种轻量的

&#x20; provenance 关联机制。



&#x20; ---

&#x20; 推荐论文章节映射



&#x20; ┌──────────────────────┬────────────────────────────────────────────────────────┐

&#x20; │       论文章节       │                        对应改动                        │

&#x20; ├──────────────────────┼────────────────────────────────────────────────────────┤

&#x20; │ 系统架构概览         │ （已有：Zeek+nDPI+ET-BERT+LLM+merge）+ 异步 web 包装   │

&#x20; ├──────────────────────┼────────────────────────────────────────────────────────┤

&#x20; │ 方法 1：分层证据融合 │ #4 分类器兜底 + #2 pre-filter triage                   │

&#x20; ├──────────────────────┼────────────────────────────────────────────────────────┤

&#x20; │ 方法 2：Agent 工程化 │ #1 工具路由 curation + #3 runtime 预算 + #6 chunk 并行 │

&#x20; ├──────────────────────┼────────────────────────────────────────────────────────┤

&#x20; │ 方法 3：鲁棒数据接入 │ #5 宽容解析 + flow\_key 白名单                          │

&#x20; ├──────────────────────┼────────────────────────────────────────────────────────┤

&#x20; │ 方法 4：可解释性设计 │ #7 trace drill-down                                    │

&#x20; ├──────────────────────┼────────────────────────────────────────────────────────┤

&#x20; │ 方法论 / 评估        │ "诊断驱动的优化"——recent.log 的工具时延归因            │

&#x20; └──────────────────────┴────────────────────────────────────────────────────────┘



&#x20; ---

