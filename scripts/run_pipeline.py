"""端到端流水线驱动：preprocess → agent → merge → viz。

用法：
    python scripts/run_pipeline.py <pcap_path> [--no-agent] [--no-viz] [--max-flows-per-chunk 25]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FINAL_RESULTS_DIR, AGENT_WORKSPACE_DIR  # noqa: E402
from core.preprocessing import init_preprocessor  # noqa: E402
from core.merge import build_final_report  # noqa: E402

logger = logging.getLogger("pipeline")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="未知流量识别端到端流水线")
    parser.add_argument("pcap_path", help="PCAP 文件路径")
    parser.add_argument("--no-agent", action="store_true", help="跳过 Agent 阶段")
    parser.add_argument("--no-viz", action="store_true", help="跳过可视化生成")
    parser.add_argument(
        "--max-flows-per-chunk",
        type=int,
        default=25,
        help="Agent 每次处理的 flow 数（控制单次 LLM 上下文）",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    args = parse_args()

    errors: list[str] = []
    pcap_path = Path(args.pcap_path).expanduser().resolve()
    if not pcap_path.is_file():
        logger.error("PCAP 不存在: %s", pcap_path)
        return 2

    # Phase 1：预处理（含分类模型回填，由 CLASSIFIER_ENABLE 控制）
    try:
        preprocessor = init_preprocessor()
        preprocess_result = preprocessor.process_pcap(pcap_path)
    except Exception as exc:
        logger.exception("预处理失败：%s", exc)
        return 1

    task_id = preprocess_result.get("task_id") or pcap_path.stem
    pcap_stem = Path(preprocess_result.get("pcap_name") or pcap_path.name).stem
    timestamp = preprocess_result.get("timestamp") or ""
    safe_ts = timestamp.replace(":", "").replace("-", "").replace(".", "")[:15]
    if not task_id or task_id == pcap_path.stem:
        task_id = f"{pcap_stem}_{safe_ts}" if safe_ts else pcap_stem

    output_dir = FINAL_RESULTS_DIR / task_id
    output_dir.mkdir(parents=True, exist_ok=True)
    final_report_path = output_dir / "final_report.json"
    agent_result_path = AGENT_WORKSPACE_DIR / "outputs" / f"{task_id}_agent_result.json"

    # Phase 2：Agent
    agent_result: dict | None = None
    if args.no_agent:
        logger.info("--no-agent 已设置，跳过 Agent 阶段")
    elif not preprocess_result.get("unknown"):
        logger.info("无未知流，跳过 Agent 阶段")
    else:
        try:
            from core.agent import run_agent_sync  # 延迟导入以避免缺 mybot 时阻塞 --no-agent
            agent_result = run_agent_sync(
                preprocess_result,
                max_flows_per_chunk=args.max_flows_per_chunk,
            )
            agent_result_path.parent.mkdir(parents=True, exist_ok=True)
            with agent_result_path.open("w", encoding="utf-8") as handle:
                json.dump(agent_result, handle, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.exception("Agent 阶段失败：%s", exc)
            errors.append(f"agent: {exc}")
            agent_result = {"schema_version": "agent_result/v1", "decisions": [], "errors": [str(exc)]}

    # Phase 3：合并
    try:
        final_report = build_final_report(
            preprocess_result,
            agent_result,
            preprocess_result_ref=str(_resolve_preprocess_ref(task_id)),
            agent_result_ref=str(agent_result_path) if agent_result is not None else None,
        )
    except Exception as exc:
        logger.exception("合并失败：%s", exc)
        return 1

    final_report.setdefault("errors", []).extend(errors)
    _dump_json(final_report_path, final_report)

    # Phase 4：可视化
    if not args.no_viz:
        try:
            from core.visualization import (
                render_app_pie,
                render_app_service_sankey,
                render_service_type_bar,
            )
            viz_paths = {
                "pie": render_app_pie(final_report, output_dir / "app_pie.html"),
                "bar": render_service_type_bar(final_report, output_dir / "service_type_bar.html"),
                "sankey": render_app_service_sankey(final_report, output_dir / "app_service_sankey.html"),
            }
            final_report["artifacts"]["viz"] = viz_paths
            _dump_json(final_report_path, final_report)
        except Exception as exc:
            logger.exception("可视化失败：%s", exc)
            final_report.setdefault("errors", []).append(f"viz: {exc}")
            _dump_json(final_report_path, final_report)

    # 总结
    stats = final_report.get("stats", {})
    print("\n=== 流水线完成 ===")
    print(f"PCAP: {final_report.get('pcap_name')}")
    print(f"已知 / 未知 / Agent 标注: {stats.get('known_count', 0)} / {stats.get('unknown_count', 0)} / {stats.get('agent_labeled_count', 0)}")
    print(f"FinalReport: {final_report_path}")
    viz = final_report.get("artifacts", {}).get("viz") or {}
    for name, path in viz.items():
        if path:
            print(f"  viz.{name}: {path}")
    if final_report.get("errors"):
        print("Errors:")
        for err in final_report["errors"]:
            print(f"  - {err}")
    return 0


def _dump_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def _resolve_preprocess_ref(task_id: str) -> Path:
    from config import PROCESSED_RESULTS_DIR
    return PROCESSED_RESULTS_DIR / f"{task_id}.json"


if __name__ == "__main__":
    raise SystemExit(main())
