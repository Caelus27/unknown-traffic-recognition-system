"""读取 mybot 在 outputs/ 下写出的 AgentResult/v1 文件并合并成单个结果。"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable

from core.agent.schema import SERVICE_TYPE_VOCAB, AgentDecision

logger = logging.getLogger(__name__)


_LINE_COMMENT_RE = re.compile(r"(?m)(?<!:)//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
_MARKDOWN_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?|\n?```\s*$", re.IGNORECASE | re.MULTILINE)


def parse_agent_outputs(
    output_paths: Iterable[Path],
    *,
    pcap_name: str | None = None,
    timestamp: str | None = None,
    valid_flow_keys: set[str] | None = None,
) -> dict[str, Any]:
    """读取一组 LLM 输出 JSON，合并成 AgentResult/v1。

    valid_flow_keys: 若提供，则只保留 flow_key 在白名单中的 decision；
    对 LLM 编造的 flow_key 直接丢弃并记入 errors。
    """
    decisions: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_keys: set[str] = set()

    for path in output_paths:
        path = Path(path)
        if not path.is_file():
            errors.append(f"missing output file: {path.name}")
            continue
        raw_text = path.read_text(encoding="utf-8")
        payload, parse_err = _load_lenient(raw_text)
        if payload is None:
            errors.append(f"invalid JSON in {path.name}: {parse_err}")
            continue
        if parse_err:
            logger.warning("recovered malformed JSON in %s: %s", path.name, parse_err)
            errors.append(f"recovered malformed JSON in {path.name}: {parse_err}")

        hallucinated = 0
        for raw in _iter_raw_decisions(payload):
            normalized = _normalize_decision(raw)
            if not normalized:
                continue
            flow_key = normalized.get("flow_key")
            if valid_flow_keys is not None and flow_key not in valid_flow_keys:
                hallucinated += 1
                continue
            if flow_key and flow_key in seen_keys:
                continue
            if flow_key:
                seen_keys.add(flow_key)
            decisions.append(normalized)
        if hallucinated:
            errors.append(
                f"{path.name}: dropped {hallucinated} decision(s) with hallucinated flow_key"
            )

    return {
        "schema_version": "agent_result/v1",
        "pcap_name": pcap_name,
        "timestamp": timestamp,
        "decisions": decisions,
        "errors": errors,
    }


def _load_lenient(raw: str) -> tuple[Any, str | None]:
    """尝试用宽松规则解析 LLM 输出 JSON。

    依次尝试：原文 → 去 markdown 围栏 → 去 // 与 /* */ 注释 → 去末尾逗号。
    返回 (payload, recovery_note)。recovery_note 非空表示走了恢复路径。
    """
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        last_err = str(exc)

    cleaned = _MARKDOWN_FENCE_RE.sub("", raw).strip()
    cleaned = _LINE_COMMENT_RE.sub("", cleaned)
    cleaned = _BLOCK_COMMENT_RE.sub("", cleaned)
    cleaned = _TRAILING_COMMA_RE.sub(r"\1", cleaned)
    try:
        return json.loads(cleaned), f"stripped comments/fences (orig: {last_err})"
    except json.JSONDecodeError as exc:
        last_err = str(exc)

    # 最后兜底：从第一个 { 截取到最后一个 }，对付 LLM 在 JSON 前后多说话
    first = cleaned.find("{")
    last = cleaned.rfind("}")
    if first != -1 and last != -1 and last > first:
        snippet = cleaned[first : last + 1]
        try:
            return json.loads(snippet), f"trimmed to outer braces (orig: {last_err})"
        except json.JSONDecodeError as exc:
            last_err = str(exc)

    return None, last_err


def _iter_raw_decisions(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("decisions"), list):
            yield from (item for item in payload["decisions"] if isinstance(item, dict))
            return
        if "flow_key" in payload:
            yield payload
            return
    if isinstance(payload, list):
        yield from (item for item in payload if isinstance(item, dict))


def _normalize_decision(raw: dict[str, Any]) -> dict[str, Any] | None:
    flow_key = raw.get("flow_key")
    if not flow_key:
        return None

    final_label = raw.get("final_label")
    app = raw.get("app")
    service_type = raw.get("service_type")
    if final_label and (not app or not service_type) and ":" in final_label:
        head, tail = final_label.split(":", 1)
        app = app or head.strip() or None
        service_type = service_type or tail.strip() or None
    if app and service_type and not final_label:
        final_label = f"{app}:{service_type}"
    if service_type and service_type not in SERVICE_TYPE_VOCAB:
        logger.warning("service_type 不在词表内，置 null: %s", service_type)
        service_type = None
        if final_label and ":" in final_label:
            final_label = None

    confidence = raw.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None
    if confidence is not None:
        confidence = max(0.0, min(1.0, confidence))

    decision = {
        "flow_key": flow_key,
        "final_label": final_label,
        "app": app,
        "service_type": service_type,
        "confidence": confidence,
        "reason": raw.get("reason"),
        "evidence": _normalize_evidence(raw.get("evidence")),
        "tool_trace": raw.get("tool_trace") or {},
    }
    # 对 schema 校验做一道兜底：如果 service_type 字段被填了非词表值，AgentDecision 会拒绝。
    try:
        AgentDecision(**decision)
    except Exception as exc:
        logger.warning("decision 不符合 schema, 已剔除 service_type/final_label: %s", exc)
        decision["service_type"] = None
        decision["final_label"] = None
    return decision


def _normalize_evidence(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "source": item.get("source") or "unknown",
                "value": item.get("value"),
                "weight": item.get("weight"),
            }
        )
    return out
