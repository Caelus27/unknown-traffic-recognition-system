"""把 mybot SDK 包装成"PreprocessResult/v1 -> AgentResult/v1"的稳定入口。"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from config import AGENT_WORKSPACE_DIR, MYBOT_CONFIG_PATH
from core.agent.input_builder import build_agent_input
from core.agent.result_parser import parse_agent_outputs
from core.agent.schema import SERVICE_TYPE_VOCAB

logger = logging.getLogger(__name__)


# 当 LLM 返回 final_label=null 时，若分类模型概率 >= 这个阈值，
# runner 会用 model_label 兜底为 "unknown:<service_type>"，提高覆盖率。
_FALLBACK_MODEL_PROB_THRESHOLD = 0.5

# 一条 unknown flow 满足"任意一条 agentable 信号"才送 LLM。
# 都不满足 → 直接合成 null decision，省 token + 时间。
_AGENTABLE_PROB_THRESHOLD = 0.5
_AGENTABLE_MIN_BYTES_NO_HINT = 256

# chunk 间并行上限：默认 3 条 chunk 同时跑 LLM。可用 AGENT_CHUNK_CONCURRENCY 覆盖。
_DEFAULT_CHUNK_CONCURRENCY = 3


_PROMPT_TEMPLATE = """你是网络流量取证分析助手，需要把"未知流量"标注为复合标签 <app>:<service_type>。

工作流：
1. 必须先用 read_file **一次性整文件读完** 输入：{input_relpath}
   ——禁止分页（offset/limit）；禁止用 exec cat / exec python3 -c "json.load(...)" 重复解析；
   ——输出里的 flow_key 必须是从输入文件 flows[].flow_key 字段**逐字符复制**得到的。
2. 阅读 ./AGENTS.md 与 ./skills/traffic_classify/SKILL.md 中的规则。
3. 对 flows[] 中的**每一条**都要给出一个 decision（共 {flow_count} 条）。
   按优先级 sni > mcp_firecrawl_scrape > mcp_ip2location（IP 归属）> whois/dns（仅 FQDN）> behavior_stats > classification_model 做判断。
4. service_type 必须从词表中选取（见 input.job.policy.service_type_vocab）：bulk-transfer / interactive / stream / vpn / web。
5. 把决策结果（AgentResult/v1 schema）用 write_file 写到：{output_relpath}

工具路由（必须遵守，否则一条 chunk 会跑十几分钟）：
| 任务 | 用 | 别用 |
|---|---|---|
| 读 chunk 输入 | `read_file`（一次性） | `exec`、分页 read_file `.mybot/tool-results/*.txt` |
| **IP → ASN/ISP/国家** | `mcp_ip2location_get_geolocation({{"ip":"<单个 IP>"}})` | `web_search "1.2.3.4 owner"`、`web_fetch ip-info-page`、`whois_lookup(IP)` |
| 域名页面/标题/证书 | `mcp_firecrawl-mcp_firecrawl_scrape({{"url":"https://<sni>/"}})` | `web_fetch`（仅作 firecrawl 失败时备用） |
| 域名搜索 | `mcp_firecrawl-mcp_firecrawl_search({{"query":"...","limit":3}})` | `web_search` |
| 域名 WHOIS/DNS（仅 FQDN） | `whois_lookup({{"domain":"foo.com"}})` / `dns_records({{"domain":"foo.com"}})` | 同左但传 IP（运行时硬拒） |
| 写决策 | `write_file` | `exec echo > file` |

外部调用预算（运行时已硬性强制，超额会立刻收到 Error: 形式的工具结果，浪费 token）：
- 同 (tool, arg) 重复 ≤ 2 次。
- 对同一目标（IP / 域名），所有外部工具（含 web_*、whois、dns_*、mcp_firecrawl_*、mcp_ip2location_*）合计 ≤ 2 次。
- 域名工具收到 IP 字面量 → 立刻拒；IP 归属请用 `mcp_ip2location_get_geolocation`，**每次只传一个 IP**，不要拼成逗号串。
- 一条 flow 实在没线索（无 SNI/host/dns、分类模型也没输出）就直接 final_label=null，不要反复试错。

写入的 JSON 结构示例：
{{
  "schema_version": "agent_result/v1",
  "decisions": [
    {{
      "flow_key": "...（必须与输入完全一致，禁止编造或修改任何字符）",
      "final_label": "<app>:<service_type>",
      "app": "...",
      "service_type": "web",
      "confidence": 0.0-1.0,
      "reason": "证据摘要",
      "evidence": [{{"source": "sni|cert|ip2location|firecrawl|ndpi|classification_model", "value": "...", "weight": 0-1}}]
    }}
  ]
}}

严格要求（违反任意一条都会导致结果被丢弃）：
- 只输出**纯 JSON**到指定文件：禁止任何 // 或 /* */ 注释、禁止 markdown 围栏、禁止占位符如"其他XX条决策将在这里添加"。
- decisions 数组必须包含输入文件里**全部** {flow_count} 条 flow，**flow_key 一字不差**地复制。
- 不要臆测：缺少强证据时把 final_label/app/service_type 置 null，并在 reason 中说明（仍要写入该条 decision，不可省略）。
- **禁止使用 `exec` 工具**——你不需要 shell。
- 完成后用一句话告诉我已写入哪个文件以及包含多少条 decision。
"""


async def run_agent(
    preprocess_result: dict[str, Any],
    *,
    mybot_config_path: Path | str | None = None,
    workspace: Path | str | None = None,
    session_prefix: str = "traffic",
    max_flows_per_chunk: int = 25,
) -> dict[str, Any]:
    """对单个 PreprocessResult 跑一遍 Agent 推断，返回 AgentResult/v1。"""

    workspace_path = Path(workspace or AGENT_WORKSPACE_DIR).expanduser().resolve()
    inputs_dir = workspace_path / "inputs"
    outputs_dir = workspace_path / "outputs"
    outputs_dir.mkdir(parents=True, exist_ok=True)

    pcap_name = preprocess_result.get("pcap_name") or "unknown.pcap"
    timestamp = preprocess_result.get("timestamp") or ""

    unknown_flows = list(preprocess_result.get("unknown") or [])
    if not unknown_flows:
        logger.info("无未知流，Agent 阶段跳过")
        return {
            "schema_version": "agent_result/v1",
            "pcap_name": pcap_name,
            "timestamp": timestamp,
            "decisions": [],
            "errors": [],
        }

    # ---- pre-filter: 把"喂 LLM 也必为 null"的 flow 抠出来，直接合成 null decision ----
    agentable, doomed = _partition_agentable(unknown_flows)
    skipped_decisions = [
        {
            "flow_key": flow.get("flow_key"),
            "final_label": None,
            "app": None,
            "service_type": None,
            "confidence": 0.0,
            "reason": _doomed_reason(flow),
            "evidence": [],
            "tool_trace": {"prefilter": "skipped_unidentifiable"},
        }
        for flow in doomed
        if flow.get("flow_key")
    ]
    logger.info(
        "Agent 输入分流：agentable=%d，pre-filtered(no-evidence)=%d，total unknown=%d",
        len(agentable),
        len(doomed),
        len(unknown_flows),
    )

    if not agentable:
        # 没有任何 flow 值得喂 LLM。直接返回合成结果。
        return {
            "schema_version": "agent_result/v1",
            "pcap_name": pcap_name,
            "timestamp": timestamp,
            "decisions": skipped_decisions,
            "errors": [
                f"pre-filtered {len(doomed)} flow(s) as unidentifiable; LLM not invoked"
            ]
            if doomed
            else [],
        }

    # build_agent_input 只看 preprocess_result['unknown']；用浅拷贝替换它
    filtered_preprocess = dict(preprocess_result)
    filtered_preprocess["unknown"] = agentable
    input_paths = build_agent_input(
        filtered_preprocess,
        inputs_dir=inputs_dir,
        max_flows_per_chunk=max_flows_per_chunk,
    )

    try:
        from mybot import MyBot
    except ImportError as exc:
        raise RuntimeError(
            "无法导入 mybot 包；请运行 `pip install -e mybot-main` 后重试"
        ) from exc

    config_path = Path(mybot_config_path or MYBOT_CONFIG_PATH).expanduser()
    if not config_path.is_file():
        raise FileNotFoundError(
            f"mybot 配置文件不存在: {config_path}；请先创建 agent_workspace/config.json"
        )

    bot = MyBot.from_config(config_path=config_path, workspace=workspace_path)

    # 预读所有 chunk 输入：拿 valid_flow_keys（防 LLM 编造）+ flow_index（兜底用）
    output_paths: list[Path] = []
    pcap_stem = Path(pcap_name).stem
    valid_flow_keys: set[str] = set()
    flow_index: dict[str, dict[str, Any]] = {}
    chunk_specs: list[dict[str, Any]] = []

    for input_path in input_paths:
        chunk_index = input_path.stem.rsplit("_chunk_", 1)[-1]
        output_path = outputs_dir / f"{input_path.stem}_result.json"
        output_paths.append(output_path)

        chunk_flows: list[dict[str, Any]] = []
        try:
            with input_path.open("r", encoding="utf-8") as handle:
                chunk_payload = json.load(handle)
            chunk_flows = (chunk_payload.get("job") or {}).get("flows") or []
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("无法预读 chunk 输入 %s: %s", input_path.name, exc)
        for f in chunk_flows:
            if isinstance(f, dict) and f.get("flow_key"):
                valid_flow_keys.add(f["flow_key"])
                flow_index[f["flow_key"]] = f

        prompt = _PROMPT_TEMPLATE.format(
            input_relpath=str(input_path.relative_to(workspace_path)),
            output_relpath=str(output_path.relative_to(workspace_path)),
            flow_count=len(chunk_flows),
        )
        chunk_specs.append(
            {
                "chunk_index": chunk_index,
                "output_path": output_path,
                "prompt": prompt,
                "session_key": f"{session_prefix}:{pcap_stem}:{timestamp}:chunk{chunk_index}",
            }
        )

    # ---- chunk 间并行 ----
    try:
        concurrency = max(1, int(os.getenv("AGENT_CHUNK_CONCURRENCY", _DEFAULT_CHUNK_CONCURRENCY)))
    except ValueError:
        concurrency = _DEFAULT_CHUNK_CONCURRENCY
    concurrency = min(concurrency, len(chunk_specs))
    semaphore = asyncio.Semaphore(concurrency)
    logger.info(
        "Agent 调用 %d 个 chunk，并行度=%d (AGENT_CHUNK_CONCURRENCY)",
        len(chunk_specs),
        concurrency,
    )

    async def _run_one_chunk(spec: dict[str, Any]) -> None:
        async with semaphore:
            chunk_index = spec["chunk_index"]
            output_path: Path = spec["output_path"]
            logger.info("Agent 处理 chunk %s -> %s", chunk_index, output_path.name)
            try:
                await bot.run(spec["prompt"], session_key=spec["session_key"])
            except Exception as exc:  # noqa: BLE001
                logger.exception("mybot 运行失败 chunk=%s: %s", chunk_index, exc)
                # 不阻塞其他 chunk；用空 outputs 占位，由 parser 收集错误
                output_path.write_text(
                    json.dumps(
                        {
                            "schema_version": "agent_result/v1",
                            "decisions": [],
                            "errors": [str(exc)],
                        }
                    ),
                    encoding="utf-8",
                )

    await asyncio.gather(*(_run_one_chunk(spec) for spec in chunk_specs))

    parsed = parse_agent_outputs(
        output_paths,
        pcap_name=pcap_name,
        timestamp=timestamp,
        valid_flow_keys=valid_flow_keys or None,
    )
    _apply_classifier_fallback(parsed, flow_index)

    # 把 pre-filter 合成的 null decisions 拼进结果（紧跟 LLM 决策之后）
    if skipped_decisions:
        parsed.setdefault("decisions", []).extend(skipped_decisions)
        parsed.setdefault("errors", []).append(
            f"pre-filtered {len(skipped_decisions)} flow(s) as unidentifiable "
            "(no SNI/host/dns and no classification_model evidence)"
        )

    return parsed


def _is_agentable(flow: dict[str, Any]) -> bool:
    """判断这条未知 flow 是否值得送 LLM。

    任一条满足即认为有戏：
    - 有 SNI / SAN
    - 有 HTTP host / DNS query
    - 分类模型给出概率 ≥ 阈值的标签
    - ndpi_app 不是泛型占位（TLS / TCP / UDP / Unknown）
    - 流量字节数足够大（默认 ≥ 256B）暗示有真实业务交互
    """

    if flow.get("sni"):
        return True
    tls = flow.get("tls") or {}
    if (tls.get("server_name") and tls.get("server_name") != flow.get("sni")) or tls.get("san_dns"):
        return True
    http = flow.get("http") or {}
    if http.get("host") or http.get("uri"):
        return True
    dns = flow.get("dns") or {}
    if dns.get("query"):
        return True

    # ET-BERT 模型给出可信标签
    cm_label = (flow.get("model_label") or "").strip().lower()
    cm_prob = flow.get("model_probability")
    try:
        cm_prob_f = float(cm_prob) if cm_prob is not None else 0.0
    except (TypeError, ValueError):
        cm_prob_f = 0.0
    if cm_label and cm_label in SERVICE_TYPE_VOCAB and cm_prob_f >= _AGENTABLE_PROB_THRESHOLD:
        return True

    # 协议栈 / nDPI 不是泛型
    ndpi = (flow.get("ndpi_app") or "").strip()
    proto = (flow.get("proto_stack") or "").strip()
    generic = {"", "tls", "tcp", "udp", "unknown", "unknown.unknown"}
    if ndpi.lower() not in generic or proto.lower() not in generic:
        if ndpi.lower() not in generic:
            return True

    # 字节数兜底：足够大 → 真实业务，仍值得让 LLM 看一眼
    stats = flow.get("stats") or {}
    try:
        total_bytes = int(stats.get("total_bytes") or 0)
    except (TypeError, ValueError):
        total_bytes = 0
    if total_bytes >= _AGENTABLE_MIN_BYTES_NO_HINT and (stats.get("s_to_c_bytes") or 0):
        return True

    return False


def _partition_agentable(
    flows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    agentable: list[dict[str, Any]] = []
    doomed: list[dict[str, Any]] = []
    for flow in flows:
        (agentable if _is_agentable(flow) else doomed).append(flow)
    return agentable, doomed


def _doomed_reason(flow: dict[str, Any]) -> str:
    """给 pre-filter 跳过的 flow 写一句可读的"为什么没让 LLM 看"。"""
    stats = flow.get("stats") or {}
    bits: list[str] = []
    if not flow.get("sni"):
        bits.append("无 SNI")
    if not (flow.get("http") or {}).get("host"):
        bits.append("无 HTTP host")
    if not (flow.get("dns") or {}).get("query"):
        bits.append("无 DNS query")
    if not flow.get("model_label"):
        bits.append("分类模型无输出")
    try:
        total_bytes = int(stats.get("total_bytes") or 0)
    except (TypeError, ValueError):
        total_bytes = 0
    bits.append(f"total_bytes={total_bytes}")
    if (stats.get("s_to_c_bytes") or 0) == 0:
        bits.append("s_to_c_bytes=0（疑似握手未完成）")
    return "pre-filtered: " + "; ".join(bits)


def _apply_classifier_fallback(
    agent_result: dict[str, Any], flow_index: dict[str, dict[str, Any]]
) -> None:
    """对 LLM 返回 final_label=null 的 decision 做"分类模型兜底"。

    规则：
    - LLM 已经给了非空 final_label：原样保留，不动。
    - LLM 留空，但输入 flow 的 hints.classification_model 给出概率 >= 阈值 的标签
      （且标签在 service_type 词表内）：合成 "unknown:<service_type>"，
      app="unknown"、service_type=cm_label、confidence=cm_prob*0.6（衰减以
      表达"非强证据"），并在 evidence 中追加来源 classification_model。
    - 仍无可用证据 → 保持 null，由前端按 unknown_app:unknown 聚合。
    """

    if not flow_index:
        return
    filled = 0
    for decision in agent_result.get("decisions", []):
        if decision.get("final_label"):
            continue
        flow = flow_index.get(decision.get("flow_key"))
        if not flow:
            continue
        cm = (flow.get("hints") or {}).get("classification_model") or {}
        cm_label = (cm.get("label") or "").strip().lower()
        cm_prob = cm.get("probability")
        try:
            cm_prob_f = float(cm_prob) if cm_prob is not None else 0.0
        except (TypeError, ValueError):
            cm_prob_f = 0.0

        if not cm_label or cm_label not in SERVICE_TYPE_VOCAB:
            continue
        if cm_prob_f < _FALLBACK_MODEL_PROB_THRESHOLD:
            continue

        decision["service_type"] = cm_label
        decision["app"] = "unknown"
        decision["final_label"] = f"unknown:{cm_label}"
        decision["confidence"] = round(cm_prob_f * 0.6, 2)
        existing_reason = decision.get("reason") or ""
        suffix = f"runner fallback: classification_model={cm_label}@{cm_prob_f:.2f}"
        decision["reason"] = f"{existing_reason} | {suffix}".strip(" |")
        evidence = decision.get("evidence") or []
        evidence.append(
            {
                "source": "classification_model",
                "value": f"{cm_label}:{cm_prob_f:.3f}",
                "weight": round(cm_prob_f, 2),
            }
        )
        decision["evidence"] = evidence
        filled += 1

    if filled:
        logger.info("classifier fallback labeled %d additional decision(s)", filled)
        agent_result.setdefault("errors", []).append(
            f"classifier fallback labeled {filled} decision(s) the LLM left empty"
        )


def run_agent_sync(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """同步包装，便于流水线脚本直接调用。"""
    return asyncio.run(_run_agent_silenced(*args, **kwargs))


async def _run_agent_silenced(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """安装一个 asyncio 异常处理器，吞掉 MCP stdio 关闭时已知的 anyio cancel-scope 噪声。

    这些 RuntimeError 仅在事件循环关闭、MCP 子进程 stdio 还在 anyio cancel scope 内时出现，
    不影响 Agent 运行结果，但会把日志刷得很乱。
    """

    loop = asyncio.get_running_loop()
    prev_handler = loop.get_exception_handler()

    def _handler(_loop, ctx):
        exc = ctx.get("exception")
        msg = ctx.get("message", "")
        is_known_noise = (
            isinstance(exc, RuntimeError)
            and "Attempted to exit cancel scope" in str(exc)
        ) or "Attempted to exit cancel scope" in msg
        if is_known_noise:
            logger.debug("suppressed asyncio shutdown noise: %s", msg or exc)
            return
        if prev_handler is not None:
            prev_handler(_loop, ctx)
        else:
            _loop.default_exception_handler(ctx)

    loop.set_exception_handler(_handler)
    try:
        return await run_agent(*args, **kwargs)
    finally:
        loop.set_exception_handler(prev_handler)
