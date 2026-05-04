"""ET-BERT 分类模型适配器。

适配 `core/classifier/adapter.py` 定义的 ClassifierCallable 协议：
    run_etbert_classifier(manifest_path) -> list[dict]

启用方式（在运行流水线前 export 环境变量）::

    CLASSIFIER_ENABLE=true
    CLASSIFIER_ADAPTER="core.classifier.etbert_adapter:run_etbert_classifier"
    CLASSIFIER_MODEL_NAME="etbert_v1"
    # 可选：覆盖默认权重路径
    CLASSIFIER_MODEL_BIN=/path/to/best_model.bin
    CLASSIFIER_VOCAB=/path/to/encryptd_vocab.txt

内部流程：
    1. 读 manifest.json，定位本次任务的 unknown_flows_pcap 目录与 flow 列表。
    2. 用 subprocess 调用 classifier_model/generate_infer_dataset.py 生成 TSV + 推理 manifest。
    3. 用 subprocess 调用 classifier_model/run_classifier_infer.py（带 --per_pcap_output）。
    4. 把 per_pcap.json 与 manifest.json 按 flow_index 对齐，构造 ClassifierCallable 输出。

任何步骤失败时抛异常，由 core/classifier/adapter.py 上游接管错误填充。
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

from config import CLASSIFIER_MODEL_BIN, CLASSIFIER_MODEL_DIR, CLASSIFIER_MODEL_NAME, CLASSIFIER_VOCAB

logger = logging.getLogger(__name__)


GENERATE_SCRIPT = CLASSIFIER_MODEL_DIR / "generate_infer_dataset.py"
INFER_SCRIPT = CLASSIFIER_MODEL_DIR / "run_classifier_infer.py"
DEFAULT_BERT_CONFIG = CLASSIFIER_MODEL_DIR / "assets" / "models" / "bert_base_config.json"


def run_etbert_classifier(manifest_path: str | Path) -> list[dict[str, Any]]:
    manifest_path = Path(manifest_path).expanduser().resolve()
    if not manifest_path.is_file():
        raise FileNotFoundError(f"manifest 不存在: {manifest_path}")
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    task_dir_text = manifest.get("unknown_flows_pcap_dir") or str(manifest_path.parent)
    task_dir = Path(task_dir_text).expanduser().resolve()
    if not task_dir.is_dir():
        raise FileNotFoundError(f"unknown_flows_pcap_dir 不存在: {task_dir}")

    flows = manifest.get("flows") or []
    if not flows:
        logger.info("manifest 无未知流，分类模型跳过")
        return []

    if not CLASSIFIER_MODEL_BIN.is_file():
        raise FileNotFoundError(f"模型权重缺失: {CLASSIFIER_MODEL_BIN}")
    if not CLASSIFIER_VOCAB.is_file():
        raise FileNotFoundError(f"词表缺失: {CLASSIFIER_VOCAB}")
    if not GENERATE_SCRIPT.is_file() or not INFER_SCRIPT.is_file():
        raise FileNotFoundError(
            f"classifier_model 脚本缺失: {GENERATE_SCRIPT} / {INFER_SCRIPT}"
        )

    infer_workdir = task_dir / "_infer"
    infer_workdir.mkdir(parents=True, exist_ok=True)

    _run_generate_dataset(task_dir, infer_workdir)

    nolabel_tsv = infer_workdir / "nolabel_infer_dataset.tsv"
    manifest_tsv = infer_workdir / "infer_manifest.tsv"
    prediction_tsv = infer_workdir / "prediction.tsv"
    per_pcap_json = task_dir / "classifier_per_pcap.json"

    if not nolabel_tsv.is_file() or not manifest_tsv.is_file():
        raise RuntimeError(
            f"生成推理数据失败：找不到 {nolabel_tsv} 或 {manifest_tsv}"
        )

    _run_inference(nolabel_tsv, manifest_tsv, prediction_tsv, per_pcap_json)

    if not per_pcap_json.is_file():
        raise RuntimeError(f"推理脚本未产出 per-pcap 输出: {per_pcap_json}")

    with per_pcap_json.open("r", encoding="utf-8") as handle:
        per_pcap_results = json.load(handle)

    return _align_results(flows, per_pcap_results)


def _run_generate_dataset(task_dir: Path, output_dir: Path) -> None:
    cmd = [
        sys.executable,
        str(GENERATE_SCRIPT),
        "--input_path", str(task_dir),
        "--output_dir", str(output_dir),
        "--dataset_level", "packet",
        "--feature_mode", "window_payload",
        "--window_payload_packets", "5",
        "--window_payload_stride", "25",
        "--payload_length", "128",
        "--max_records_per_capture", "1500",
    ]
    logger.info("运行 generate_infer_dataset: %s", " ".join(cmd))
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"generate_infer_dataset 失败: rc={completed.returncode} stderr={completed.stderr}"
        )


def _run_inference(
    nolabel_tsv: Path,
    manifest_tsv: Path,
    prediction_tsv: Path,
    per_pcap_json: Path,
) -> None:
    cmd = [
        sys.executable,
        str(INFER_SCRIPT),
        "--load_model_path", str(CLASSIFIER_MODEL_BIN),
        "--vocab_path", str(CLASSIFIER_VOCAB),
        "--config_path", str(DEFAULT_BERT_CONFIG),
        "--test_path", str(nolabel_tsv),
        "--prediction_path", str(prediction_tsv),
        "--per_pcap_output", str(per_pcap_json),
        "--manifest_path", str(manifest_tsv),
        "--labels_num", "5",
        "--embedding", "word_pos_seg",
        "--encoder", "transformer",
        "--mask", "fully_visible",
        "--seq_length", "128",
        "--batch_size", "64",
    ]
    logger.info("运行 run_classifier_infer: %s", " ".join(cmd))
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"run_classifier_infer 失败: rc={completed.returncode} stderr={completed.stderr}"
        )


def _align_results(
    manifest_flows: list[dict[str, Any]],
    per_pcap_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_index: dict[int, dict[str, Any]] = {}
    by_pcap: dict[str, dict[str, Any]] = {}
    for entry in per_pcap_results:
        flow_index = entry.get("flow_index")
        if flow_index is not None:
            by_index[int(flow_index)] = entry
        pcap_path = entry.get("pcap_path")
        if pcap_path:
            by_pcap[str(Path(pcap_path).resolve())] = entry

    aligned: list[dict[str, Any]] = []
    for flow in manifest_flows:
        index = flow.get("index")
        flow_pcap = flow.get("unknown_pcap_path")
        match = None
        if index is not None:
            match = by_index.get(int(index))
        if match is None and flow_pcap:
            match = by_pcap.get(str(Path(flow_pcap).resolve()))

        if match is None:
            aligned.append(
                {
                    "index": index,
                    "flow_key": flow.get("flow_key"),
                    "status": "no_prediction",
                    "model_name": CLASSIFIER_MODEL_NAME,
                    "label": None,
                    "probability": None,
                    "topk": [],
                    "error": "no matching per-pcap prediction",
                }
            )
            continue

        aligned.append(
            {
                "index": index,
                "flow_key": flow.get("flow_key"),
                "status": "ok",
                "model_name": CLASSIFIER_MODEL_NAME,
                "label": match.get("label"),
                "probability": match.get("probability"),
                "topk": match.get("topk", []),
                "error": None,
            }
        )
    return aligned
