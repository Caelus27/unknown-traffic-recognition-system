from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.classifier import default_classification_result
from core.utils.helpers import dump_json_file, make_flow_key, normalize_text, safe_float, safe_int


def normalize_legacy_preprocess_result(payload: dict[str, Any], source_path: str | Path | None = None) -> dict[str, Any]:
    """Return a PreprocessResult/v1-shaped copy without modifying legacy input files."""
    normalized = {
        "schema_version": "preprocess/v1",
        "pcap_name": payload.get("pcap_name"),
        "pcap_path": payload.get("pcap_path"),
        "timestamp": payload.get("timestamp"),
        "artifacts": payload.get("artifacts") or {},
        "stats": payload.get("stats") or {},
        "known": [_normalize_flow(flow, known=True) for flow in payload.get("known", [])],
        "unknown": [_normalize_flow(flow, known=False) for flow in payload.get("unknown", [])],
    }
    if source_path is not None:
        normalized["artifacts"]["legacy_source"] = str(source_path)
    return normalized


def normalize_legacy_preprocess_file(input_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    input_path = Path(input_path)
    with input_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    normalized = normalize_legacy_preprocess_result(payload, source_path=input_path)
    if output_path is not None:
        dump_json_file(output_path, normalized)
    return normalized


def _normalize_flow(flow: dict[str, Any], known: bool) -> dict[str, Any]:
    current = dict(flow)
    stats = dict(current.get("stats") or {})
    for key in ("duration", "total_bytes", "c_to_s_bytes", "s_to_c_bytes"):
        if key in current and key not in stats:
            value = safe_float(current.get(key)) if key == "duration" else safe_int(current.get(key))
            stats[key] = value
    current["stats"] = stats

    src_ip = normalize_text(current.get("src_ip")) or "unknown"
    dst_ip = normalize_text(current.get("dst_ip")) or "unknown"
    src_port = safe_int(current.get("src_port"))
    dst_port = safe_int(current.get("dst_port"))
    transport = (normalize_text(current.get("transport")) or "unknown").lower()
    current["src_ip"] = src_ip
    current["dst_ip"] = dst_ip
    current["src_port"] = src_port
    current["dst_port"] = dst_port
    current["transport"] = transport
    current["flow_key"] = normalize_text(current.get("flow_key")) or make_flow_key(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        transport,
    )

    current.setdefault("http", {"host": None, "urls": [], "content_types": []})
    current.setdefault("dns", {"query": None, "answers": [], "queries": []})
    current.setdefault("tls", {"server_name": current.get("sni"), "san_dns": []})
    current.setdefault("reason", current.get("preprocess_reason") or "legacy flow")
    current.setdefault("evidence", {})
    current.setdefault("unknown_pcap_path", None)
    current.setdefault(
        "pcap_extraction",
        {"status": "legacy_missing", "error": None, "packet_count": 0, "byte_count": 0},
    )

    if known:
        current.setdefault("label", current.get("preprocess_label"))
    else:
        current.setdefault("classification_model", default_classification_result())
    return current

