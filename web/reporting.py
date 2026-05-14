"""把 FinalReport/v1 派生为前端 dashboard 数据 + flow detail 构造。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

_TRACE_BYTE_CAP = 5 * 1024 * 1024


def to_dashboard(final_report: dict[str, Any]) -> dict[str, Any]:
    """把 FinalReport/v1 转成前端 dashboard 需要的扁平结构。"""

    stats_in = final_report.get("stats") or {}
    aggregations = final_report.get("aggregations") or {}
    by_app_raw = aggregations.get("by_app") or {}
    by_service_raw = aggregations.get("by_service_type") or {}

    known_flows = list(final_report.get("known") or [])
    unknown_flows = list(final_report.get("unknown_labeled") or [])
    all_flows = known_flows + unknown_flows

    total_flows = int(stats_in.get("total_flows") or len(all_flows))
    known_count = int(stats_in.get("known_count") or len(known_flows))
    unknown_count = int(stats_in.get("unknown_count") or len(unknown_flows))

    total_bytes = sum(_safe_int((flow.get("stats") or {}).get("total_bytes")) for flow in all_flows)
    durations = [_safe_float((flow.get("stats") or {}).get("duration")) for flow in all_flows]
    durations = [d for d in durations if d is not None]
    avg_duration = round(sum(durations) / len(durations), 3) if durations else 0.0
    max_duration = round(max(durations), 3) if durations else 0.0

    ndpi_recognized = sum(
        1
        for flow in all_flows
        if _is_ndpi_recognized(flow.get("ndpi_app"))
    )
    ndpi_rate = _pct(ndpi_recognized, total_flows)

    by_app_list = [
        {"app": app, "count": int(count), "pct": _pct(count, total_flows)}
        for app, count in by_app_raw.items()
    ]
    by_app_list.sort(key=lambda item: -item["count"])

    unknown_results = _build_unknown_results(unknown_flows, unknown_count)

    return {
        "pcap_name": final_report.get("pcap_name"),
        "timestamp": final_report.get("timestamp"),
        "stats": {
            "total_flows": total_flows,
            "known_count": known_count,
            "known_pct": _pct(known_count, total_flows),
            "unknown_count": unknown_count,
            "unknown_pct": _pct(unknown_count, total_flows),
            "total_bytes": int(total_bytes),
            "avg_duration_sec": avg_duration,
            "max_duration_sec": max_duration,
            "unique_apps": len(by_app_raw),
            "unique_services": len(by_service_raw),
            "ndpi_recognition_rate": ndpi_rate,
            "agent_labeled_count": int(stats_in.get("agent_labeled_count") or 0),
            "agent_coverage_pct": _pct(stats_in.get("agent_labeled_count") or 0, unknown_count),
        },
        "by_app": by_app_list,
        "unknown_results": unknown_results,
        "errors": list(final_report.get("errors") or []),
    }


def build_flow_detail(
    final_report: dict[str, Any],
    flow_key: str,
    *,
    session_paths: Iterable[Path] | None = None,
    input_paths: Iterable[Path] | None = None,
) -> dict[str, Any] | None:
    """根据 flow_key 在 unknown_labeled 中精确匹配，返回详情包。

    返回 None 表示找不到该 flow（API 层应转 404）。
    """

    unknown_flows = list(final_report.get("unknown_labeled") or [])
    flow = next((item for item in unknown_flows if item.get("flow_key") == flow_key), None)
    if flow is None:
        return None

    agent_payload = {
        "final_label": flow.get("final_label"),
        "app": flow.get("app"),
        "service_type": flow.get("service_type"),
        "confidence": flow.get("confidence"),
        "reason": flow.get("reason"),
        "evidence": flow.get("evidence") or [],
        "tool_trace": flow.get("tool_trace") or {},
    }

    chunk_input, flow_in_chunk_index = _find_flow_in_inputs(flow_key, input_paths or [])
    agent_trace = _load_agent_trace(session_paths or [])

    return {
        "flow_key": flow_key,
        "flow": flow,
        "agent": agent_payload,
        "agent_input_snapshot": chunk_input,
        "flow_in_chunk_index": flow_in_chunk_index,
        "agent_trace": agent_trace,
    }


def _build_unknown_results(unknown_flows: list[dict[str, Any]], unknown_count: int) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for flow in unknown_flows:
        label = flow.get("final_label")
        app = flow.get("app") or "unknown_app"
        service = flow.get("service_type") or "unknown"
        if not label:
            label = f"{app}:{service}"
        bucket = grouped.setdefault(
            label,
            {"label": label, "app": app, "service_type": service, "count": 0, "flow_keys": []},
        )
        bucket["count"] += 1
        if flow.get("flow_key"):
            bucket["flow_keys"].append(flow["flow_key"])

    rows = list(grouped.values())
    for row in rows:
        row["pct"] = _pct(row["count"], unknown_count)
    rows.sort(key=lambda item: -item["count"])
    return rows


def _find_flow_in_inputs(
    flow_key: str, input_paths: Iterable[Path]
) -> tuple[dict[str, Any] | None, int | None]:
    for path in input_paths:
        try:
            with Path(path).open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        flows = (payload.get("job") or {}).get("flows") or []
        for idx, flow in enumerate(flows):
            if flow.get("flow_key") == flow_key:
                return payload, idx
    return None, None


def _load_agent_trace(session_paths: Iterable[Path]) -> dict[str, Any]:
    """合并多个 session jsonl，返回 {session_key, meta, messages, truncated}。

    若任务跑了多个 chunk，存在多份 jsonl；逐一拼成时间轴。
    """

    meta: dict[str, Any] = {}
    session_key: str | None = None
    messages: list[dict[str, Any]] = []
    bytes_seen = 0
    truncated = False

    for path in session_paths:
        path = Path(path)
        if not path.is_file():
            continue
        try:
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                if not raw_line.strip():
                    continue
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if record.get("_type") == "metadata":
                    if not session_key:
                        session_key = record.get("key")
                    if not meta:
                        meta = {
                            "key": record.get("key"),
                            "created_at": record.get("created_at"),
                            "updated_at": record.get("updated_at"),
                            "metadata": record.get("metadata") or {},
                            "source_file": str(path),
                        }
                    continue
                bytes_seen += len(raw_line)
                if bytes_seen > _TRACE_BYTE_CAP:
                    truncated = True
                    break
                messages.append(record)
            if truncated:
                break
        except OSError:
            continue

    return {
        "session_key": session_key,
        "meta": meta,
        "messages": messages,
        "truncated": truncated,
    }


def _pct(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return round(numerator / denominator * 100, 2)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_ndpi_recognized(ndpi_app: Any) -> bool:
    if not ndpi_app:
        return False
    if not isinstance(ndpi_app, str):
        return False
    lowered = ndpi_app.strip().lower()
    if not lowered:
        return False
    return lowered not in {"unknown", "unknown.unknown"}
