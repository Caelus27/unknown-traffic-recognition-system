from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any, Callable

from config import CLASSIFIER_ADAPTER, CLASSIFIER_ENABLE, CLASSIFIER_MODEL_NAME
from core.utils.helpers import normalize_text, safe_float, safe_int

logger = logging.getLogger(__name__)


ClassifierCallable = Callable[[str | Path], list[dict[str, Any]] | dict[str, Any]]


def default_classification_result(status: str = "not_run", error: str | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "model_name": CLASSIFIER_MODEL_NAME,
        "label": None,
        "probability": None,
        "error": error,
    }


def run_classifier_for_manifest(manifest_path: str | Path) -> dict[Any, dict[str, Any]]:
    """Run the optional Phase 1.5 classifier adapter.

    Adapter output can be:
    - list[dict]: each item may include `index` (preferred) and/or `flow_key`
    - dict: mapping from index/flow_key -> result dict
    - dict with `output`: wrapper around one of the above

    Results are normalized and indexed by both `index` (int) and `flow_key` (str) when present.
    """
    if not CLASSIFIER_ENABLE:
        return {}
    if not CLASSIFIER_ADAPTER:
        logger.warning("CLASSIFIER_ENABLE=true 但未配置 CLASSIFIER_ADAPTER，跳过分类模型")
        return {}

    try:
        adapter = _load_adapter(CLASSIFIER_ADAPTER)
        raw_results = adapter(manifest_path)
        normalized = _normalize_classifier_output(raw_results)
        logger.info("分类模型返回 %s 条结果", len(normalized))
        return normalized
    except Exception as exc:
        logger.exception("分类模型适配器执行失败: %s", exc)
        return {
            "__classifier_error__": default_classification_result(
                status="error",
                error=str(exc),
            )
        }


def apply_classification_results(
    unknown_flows: list[dict[str, Any]],
    classifier_results: dict[Any, dict[str, Any]],
) -> None:
    """Mutate unknown flow payloads with classifier placeholders or results."""
    global_error = classifier_results.get("__classifier_error__")
    for flow in unknown_flows:
        flow_index = safe_int(flow.get("unknown_pcap_index"))
        flow_key = normalize_text(flow.get("flow_key"))
        if global_error:
            flow["classification_model"] = global_error
            continue
        if flow_index is not None and flow_index in classifier_results:
            flow["classification_model"] = classifier_results[flow_index]
            continue
        if flow_key and flow_key in classifier_results:
            flow["classification_model"] = classifier_results[flow_key]
            continue
        flow["classification_model"] = default_classification_result()


def _load_adapter(adapter_path: str) -> ClassifierCallable:
    if ":" not in adapter_path:
        raise ValueError("CLASSIFIER_ADAPTER 格式应为 'module.submodule:function_name'")
    module_name, function_name = adapter_path.split(":", 1)
    module = importlib.import_module(module_name)
    adapter = getattr(module, function_name)
    if not callable(adapter):
        raise TypeError(f"{adapter_path} 不是可调用对象")
    return adapter


def _normalize_classifier_output(raw_results: list[dict[str, Any]] | dict[str, Any]) -> dict[Any, dict[str, Any]]:
    items: list[dict[str, Any]]
    if isinstance(raw_results, dict) and "output" in raw_results:
        wrapped = raw_results.get("output")
        if isinstance(wrapped, dict):
            raw_results = wrapped
        elif isinstance(wrapped, list):
            raw_results = wrapped

    if isinstance(raw_results, dict):
        items = []
        for key, value in raw_results.items():
            if isinstance(value, dict):
                enriched = dict(value)
                enriched.setdefault("_key", key)
                items.append(enriched)
    else:
        items = [item for item in raw_results if isinstance(item, dict)]

    normalized: dict[Any, dict[str, Any]] = {}
    for item in items:
        flow_index = safe_int(item.get("index"))
        if flow_index is None:
            flow_index = safe_int(item.get("unknown_pcap_index"))
        if flow_index is None:
            flow_index = safe_int(item.get("pcap_index"))
        if flow_index is None:
            flow_index = safe_int(item.get("_key"))

        flow_key = normalize_text(item.get("flow_key"))
        if not flow_key:
            candidate_key = item.get("_key")
            if isinstance(candidate_key, str) and candidate_key.strip() and safe_int(candidate_key) is None:
                flow_key = normalize_text(candidate_key)

        normalized_result = {
            "status": normalize_text(item.get("status")) or "ok",
            "model_name": normalize_text(item.get("model_name")) or CLASSIFIER_MODEL_NAME,
            "label": normalize_text(item.get("label")),
            "probability": safe_float(item.get("probability")),
            "error": normalize_text(item.get("error")),
        }

        if flow_index is not None:
            normalized[flow_index] = normalized_result
        if flow_key:
            normalized[flow_key] = normalized_result

    return normalized

