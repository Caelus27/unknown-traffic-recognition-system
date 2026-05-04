"""把 mybot SDK 包装成"PreprocessResult/v1 -> AgentResult/v1"的稳定入口。"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from config import AGENT_WORKSPACE_DIR, MYBOT_CONFIG_PATH
from core.agent.input_builder import build_agent_input
from core.agent.result_parser import parse_agent_outputs

logger = logging.getLogger(__name__)


_PROMPT_TEMPLATE = """你是网络流量取证分析助手，需要把"未知流量"标注为复合标签 <app>:<service_type>。

工作流：
1. 先用 read_file 读取输入：{input_relpath}
2. 阅读 ./AGENTS.md 与 ./skills/traffic_classify/SKILL.md 中的规则。
3. 对 flows[] 中的每一条，按优先级 sni > active_fetch > cert_or_ip > behavior_stats > classification_model 做判断。
4. service_type 必须从词表中选取（见 input.job.policy.service_type_vocab）：bulk-transfer / interactive / stream / vpn / web。
5. 把决策结果（AgentResult/v1 schema）用 write_file 写到：{output_relpath}

写入的 JSON 结构示例：
{{
  "schema_version": "agent_result/v1",
  "decisions": [
    {{
      "flow_key": "...",
      "final_label": "<app>:<service_type>",
      "app": "...",
      "service_type": "web",
      "confidence": 0.0-1.0,
      "reason": "证据摘要",
      "evidence": [{{"source": "sni|cert|port|ndpi|classification_model|active_fetch", "value": "...", "weight": 0-1}}]
    }}
  ]
}}

要求：
- 只输出 JSON 写到指定文件；无需在对话里贴大段 JSON。
- 不要臆测：缺少强证据时把 final_label/app/service_type 置 null，并在 reason 中说明。
- 完成后用一句话告诉我已写入哪个文件。
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

    if not (preprocess_result.get("unknown") or []):
        logger.info("无未知流，Agent 阶段跳过")
        return {
            "schema_version": "agent_result/v1",
            "pcap_name": pcap_name,
            "timestamp": timestamp,
            "decisions": [],
            "errors": [],
        }

    input_paths = build_agent_input(
        preprocess_result,
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

    output_paths: list[Path] = []
    pcap_stem = Path(pcap_name).stem

    for input_path in input_paths:
        chunk_index = input_path.stem.rsplit("_chunk_", 1)[-1]
        output_path = outputs_dir / f"{input_path.stem}_result.json"
        output_paths.append(output_path)

        prompt = _PROMPT_TEMPLATE.format(
            input_relpath=str(input_path.relative_to(workspace_path)),
            output_relpath=str(output_path.relative_to(workspace_path)),
        )
        session_key = f"{session_prefix}:{pcap_stem}:{timestamp}:chunk{chunk_index}"
        logger.info("Agent 处理 chunk %s -> %s", chunk_index, output_path.name)
        try:
            await bot.run(prompt, session_key=session_key)
        except Exception as exc:
            logger.exception("mybot 运行失败 chunk=%s: %s", chunk_index, exc)
            # 不阻塞后续 chunk；把错误用空的 outputs 补齐，由 parser 收集
            output_path.write_text(
                json.dumps({"schema_version": "agent_result/v1", "decisions": [], "errors": [str(exc)]}),
                encoding="utf-8",
            )

    return parse_agent_outputs(output_paths, pcap_name=pcap_name, timestamp=timestamp)


def run_agent_sync(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """同步包装，便于流水线脚本直接调用。"""
    return asyncio.run(run_agent(*args, **kwargs))
