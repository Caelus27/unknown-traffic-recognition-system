"""模块C：把 PreprocessResult/v1 + AgentResult/v1 合并成 FinalReport/v1。"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

_AGENT_SKIPPED = {
    "final_label": None,
    "app": None,
    "service_type": None,
    "confidence": None,
    "reason": "agent_skipped",
    "evidence": [],
    "tool_trace": {},
}


def build_final_report(
    preprocess_result: dict[str, Any],
    agent_result: dict[str, Any] | None = None,
    *,
    preprocess_result_ref: str | None = None,
    agent_result_ref: str | None = None,
) -> dict[str, Any]:
    """合并预处理 + Agent 结果为 FinalReport/v1。"""

    agent_result = agent_result or {"decisions": []}
    decisions_by_key = {
        decision["flow_key"]: decision
        for decision in agent_result.get("decisions", [])
        if isinstance(decision, dict) and decision.get("flow_key")
    }

    known_flows = list(preprocess_result.get("known") or [])
    unknown_flows = list(preprocess_result.get("unknown") or [])

    unknown_labeled: list[dict[str, Any]] = []
    agent_labeled_count = 0
    for flow in unknown_flows:
        flow_key = flow.get("flow_key")
        decision = decisions_by_key.get(flow_key)
        merged = dict(flow)
        if decision and decision.get("final_label"):
            agent_labeled_count += 1
            merged.update(
                {
                    "final_label": decision.get("final_label"),
                    "app": decision.get("app"),
                    "service_type": decision.get("service_type"),
                    "confidence": decision.get("confidence"),
                    "reason": decision.get("reason"),
                    "evidence": decision.get("evidence", []),
                    "tool_trace": decision.get("tool_trace", {}),
                }
            )
        else:
            merged.update(_AGENT_SKIPPED)
        unknown_labeled.append(merged)

    aggregations = _build_aggregations(known_flows, unknown_labeled)

    stats = dict(preprocess_result.get("stats") or {})
    stats["agent_labeled_count"] = agent_labeled_count

    return {
        "schema_version": "final_report/v1",
        "pcap_name": preprocess_result.get("pcap_name"),
        "timestamp": preprocess_result.get("timestamp"),
        "stats": stats,
        "known": known_flows,
        "unknown_labeled": unknown_labeled,
        "aggregations": aggregations,
        "artifacts": {
            "preprocess_result_ref": preprocess_result_ref,
            "agent_result_ref": agent_result_ref,
            "viz": {"pie": None, "bar": None, "sankey": None},
        },
        "errors": list(agent_result.get("errors") or []),
    }


def _build_aggregations(
    known_flows: list[dict[str, Any]],
    unknown_labeled: list[dict[str, Any]],
) -> dict[str, Any]:
    by_app: Counter[str] = Counter()
    by_service: Counter[str] = Counter()
    cross: dict[tuple[str, str], int] = defaultdict(int)

    for flow in known_flows:
        label = flow.get("label") or flow.get("preprocess_label") or "unknown_app:unknown"
        app, service = _split_label(label)
        by_app[app] += 1
        by_service[service] += 1
        cross[(app, service)] += 1

    for flow in unknown_labeled:
        app = flow.get("app") or "unknown_app"
        service = flow.get("service_type") or "unknown"
        by_app[app] += 1
        by_service[service] += 1
        cross[(app, service)] += 1

    return {
        "by_app": dict(by_app.most_common()),
        "by_service_type": dict(by_service.most_common()),
        "app_to_service_type": [
            {"app": app, "service_type": service, "count": count}
            for (app, service), count in sorted(cross.items(), key=lambda item: -item[1])
        ],
    }


def _split_label(label: str) -> tuple[str, str]:
    if not isinstance(label, str) or ":" not in label:
        return (label or "unknown_app", "unknown")
    head, tail = label.split(":", 1)
    return (head.strip() or "unknown_app", tail.strip() or "unknown")
