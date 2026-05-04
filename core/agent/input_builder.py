"""把 PreprocessResult/v1 整形为 AgentInputJob/v1（瘦身、分块、落盘）。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.agent.schema import SERVICE_TYPE_VOCAB

_PRIORITY = ["sni", "active_fetch", "cert_or_ip", "behavior_stats", "classification_model"]


def build_agent_input(
    preprocess_result: dict[str, Any],
    *,
    inputs_dir: Path,
    max_flows_per_chunk: int = 25,
    offline_mode: bool = False,
) -> list[Path]:
    """把 unknown 流分块写到 inputs_dir/<pcap_stem>_<ts>_chunk_<N>.json。

    返回写入的文件路径列表，便于后续 runner 逐块调用 LLM。
    """
    inputs_dir = Path(inputs_dir).expanduser()
    inputs_dir.mkdir(parents=True, exist_ok=True)

    pcap_name = preprocess_result.get("pcap_name") or "unknown.pcap"
    pcap_stem = Path(pcap_name).stem
    timestamp = preprocess_result.get("timestamp") or ""
    safe_ts = timestamp.replace(":", "").replace("-", "").replace(".", "")[:15]

    unknown_flows = preprocess_result.get("unknown") or []
    if not unknown_flows:
        return []

    base_job = {
        "pcap_name": pcap_name,
        "timestamp": timestamp,
        "policy": {
            "label_format": "<app>:<service_type>",
            "service_type_vocab": list(SERVICE_TYPE_VOCAB),
            "priority": _PRIORITY,
            "offline_mode": offline_mode,
        },
    }

    paths: list[Path] = []
    for chunk_index, start in enumerate(range(0, len(unknown_flows), max_flows_per_chunk), start=1):
        chunk_flows = unknown_flows[start : start + max_flows_per_chunk]
        slim_flows = [_slim_flow(flow) for flow in chunk_flows]
        chunk_job = dict(base_job)
        chunk_job["chunk_index"] = chunk_index
        chunk_job["chunk_size"] = len(slim_flows)
        chunk_job["flows"] = slim_flows

        payload = {
            "schema_version": "agent_input/v1",
            "job": chunk_job,
        }
        path = inputs_dir / f"{pcap_stem}_{safe_ts}_chunk_{chunk_index:02d}.json"
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        paths.append(path)
    return paths


def _slim_flow(flow: dict[str, Any]) -> dict[str, Any]:
    stats = flow.get("stats") or {}
    http = flow.get("http") or {}
    dns = flow.get("dns") or {}
    tls = flow.get("tls") or {}

    return {
        "flow_key": flow.get("flow_key"),
        "transport": flow.get("transport"),
        "src": {"ip": flow.get("src_ip"), "port": flow.get("src_port")},
        "dst": {"ip": flow.get("dst_ip"), "port": flow.get("dst_port")},
        "hints": {
            "is_encrypted": flow.get("is_encrypted"),
            "sni": flow.get("sni"),
            "http_host": http.get("host"),
            "http_user_agent": http.get("user_agent"),
            "http_method": http.get("method"),
            "http_status_code": http.get("status_code"),
            "dns_query": dns.get("query"),
            "tls_version": tls.get("version"),
            "tls_alpn": tls.get("negotiated_alpn"),
            "tls_san_dns": tls.get("san_dns") or [],
            "ndpi_app": flow.get("ndpi_app"),
            "proto_stack": flow.get("proto_stack"),
            "classification_model": {
                "label": flow.get("model_label"),
                "probability": flow.get("model_probability"),
            },
        },
        "stats": {
            "duration": stats.get("duration"),
            "total_bytes": stats.get("total_bytes"),
            "c_to_s_bytes": stats.get("c_to_s_bytes"),
            "s_to_c_bytes": stats.get("s_to_c_bytes"),
            "c_to_s_packets": stats.get("c_to_s_packets"),
            "s_to_c_packets": stats.get("s_to_c_packets"),
            "data_ratio": stats.get("data_ratio"),
        },
        "preprocess": {
            "reason": flow.get("reason") or flow.get("preprocess_reason"),
            "evidence": flow.get("evidence") or {},
        },
    }
