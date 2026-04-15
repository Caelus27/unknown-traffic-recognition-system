from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any, Callable

from config import CLASSIFIER_ADAPTER, CLASSIFIER_ENABLE, CLASSIFIER_MODEL_NAME
from core.utils.helpers import normalize_text, safe_float

logger = logging.getLogger(__name__)


ClassifierCallable = Callable[[str | Path], list[dict[str, Any]] | dict[str, Any]]


def default_classification_result(status: str = "not_run", error: str | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "model_name": None,
        "label": None,
        "probability": None,
        "topk": [],
        "error": error,
    }


def run_classifier_for_manifest(manifest_path: str | Path) -> dict[str, dict[str, Any]]:
    """Run the optional Phase 1.5 classifier adapter and index results by flow_key."""
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
    classifier_results: dict[str, dict[str, Any]],
) -> None:
    """Mutate unknown flow payloads with classifier placeholders or results."""
    global_error = classifier_results.get("__classifier_error__")
    for flow in unknown_flows:
        flow_key = normalize_text(flow.get("flow_key"))
        if global_error:
            flow["classification_model"] = global_error
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


def _normalize_classifier_output(raw_results: list[dict[str, Any]] | dict[str, Any]) -> dict[str, dict[str, Any]]:
    if isinstance(raw_results, dict) and "output" in raw_results:
        items = raw_results.get("output") or []
    elif isinstance(raw_results, dict):
        items = list(raw_results.values())
    else:
        items = raw_results

    normalized: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        flow_key = normalize_text(item.get("flow_key"))
        if not flow_key:
            continue
        normalized[flow_key] = {
            "status": normalize_text(item.get("status")) or "ok",
            "model_name": normalize_text(item.get("model_name")) or CLASSIFIER_MODEL_NAME,
            "label": normalize_text(item.get("label")),
            "probability": safe_float(item.get("probability")),
            "topk": item.get("topk") if isinstance(item.get("topk"), list) else [],
            "error": normalize_text(item.get("error")),
        }
    return normalized

