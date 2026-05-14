"""异步任务管理：跑流水线并跟踪状态 / session 路径。"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import (
    AGENT_WORKSPACE_DIR,
    FINAL_RESULTS_DIR,
    PROCESSED_RESULTS_DIR,
)

logger = logging.getLogger("web.tasks")

UPLOAD_DIR = FINAL_RESULTS_DIR.parent / "sample_pcaps" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

_PIPELINE_SEMAPHORE_SIZE = 2
_PROGRESS = {
    "queued": "排队中",
    "preprocess": "预处理中",
    "agent": "Agent 推理中",
    "merge": "合并中",
    "viz": "生成可视化产物中",
    "done": "完成",
}


@dataclass
class TaskRecord:
    task_id: str
    upload_path: Path
    display_name: str
    status: str = "pending"
    progress_msg: str = "排队中"
    error: str | None = None
    final_report: dict[str, Any] | None = None
    final_report_path: Path | None = None
    session_paths: list[str] = field(default_factory=list)
    input_paths: list[str] = field(default_factory=list)
    output_paths: list[str] = field(default_factory=list)
    use_agent: bool = True
    use_viz: bool = False
    max_flows_per_chunk: int = 25
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress_msg": self.progress_msg,
            "display_name": self.display_name,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class TaskRegistry:
    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(_PIPELINE_SEMAPHORE_SIZE)
        self._executor = ThreadPoolExecutor(
            max_workers=_PIPELINE_SEMAPHORE_SIZE,
            thread_name_prefix="pipeline",
        )

    def create(
        self,
        upload_path: Path,
        display_name: str,
        *,
        use_agent: bool,
        use_viz: bool,
        max_flows_per_chunk: int,
    ) -> TaskRecord:
        task_id = uuid.uuid4().hex
        record = TaskRecord(
            task_id=task_id,
            upload_path=upload_path,
            display_name=display_name,
            use_agent=use_agent,
            use_viz=use_viz,
            max_flows_per_chunk=max_flows_per_chunk,
        )
        with self._lock:
            self._tasks[task_id] = record
        return record

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            return self._tasks.get(task_id)

    def submit(self, record: TaskRecord) -> asyncio.Future:
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(self._executor, self._run_pipeline, record)

    # --- internal ---

    def _set(self, record: TaskRecord, **fields: Any) -> None:
        with self._lock:
            for key, value in fields.items():
                setattr(record, key, value)

    def _run_pipeline(self, record: TaskRecord) -> None:
        with self._semaphore:
            try:
                self._set(record, status="running", progress_msg=_PROGRESS["preprocess"])
                self._do_run(record)
            except Exception as exc:  # noqa: BLE001
                logger.exception("pipeline failed for task %s: %s", record.task_id, exc)
                self._set(
                    record,
                    status="failed",
                    error=str(exc),
                    progress_msg=f"失败：{exc}",
                    finished_at=time.time(),
                )

    def _do_run(self, record: TaskRecord) -> None:
        from core.preprocessing import init_preprocessor
        from core.merge import build_final_report

        sessions_dir = (AGENT_WORKSPACE_DIR / "sessions").resolve()
        sessions_dir.mkdir(parents=True, exist_ok=True)
        before_session_files = _snapshot_dir(sessions_dir)

        preprocessor = init_preprocessor()
        preprocess_result = preprocessor.process_pcap(record.upload_path)

        pcap_stem = Path(preprocess_result.get("pcap_name") or record.upload_path.name).stem
        timestamp = preprocess_result.get("timestamp") or ""
        safe_ts = timestamp.replace(":", "").replace("-", "").replace(".", "")[:15]
        pipeline_task_id = preprocess_result.get("task_id") or pcap_stem
        if not pipeline_task_id or pipeline_task_id == record.upload_path.stem:
            pipeline_task_id = f"{pcap_stem}_{safe_ts}" if safe_ts else pcap_stem

        output_dir = FINAL_RESULTS_DIR / pipeline_task_id
        output_dir.mkdir(parents=True, exist_ok=True)
        final_report_path = output_dir / "final_report.json"
        agent_result_path = AGENT_WORKSPACE_DIR / "outputs" / f"{pipeline_task_id}_agent_result.json"

        agent_result: dict[str, Any] | None = None
        if record.use_agent and preprocess_result.get("unknown"):
            self._set(record, progress_msg=_PROGRESS["agent"])
            try:
                from core.agent import run_agent_sync

                agent_result = run_agent_sync(
                    preprocess_result,
                    max_flows_per_chunk=record.max_flows_per_chunk,
                )
                agent_result_path.parent.mkdir(parents=True, exist_ok=True)
                with agent_result_path.open("w", encoding="utf-8") as handle:
                    json.dump(agent_result, handle, ensure_ascii=False, indent=2)
            except Exception as exc:  # noqa: BLE001
                logger.exception("agent stage failed: %s", exc)
                agent_result = {
                    "schema_version": "agent_result/v1",
                    "decisions": [],
                    "errors": [str(exc)],
                }
        elif not record.use_agent:
            logger.info("task %s: agent skipped by user flag", record.task_id)

        self._set(record, progress_msg=_PROGRESS["merge"])
        final_report = build_final_report(
            preprocess_result,
            agent_result,
            preprocess_result_ref=str(PROCESSED_RESULTS_DIR / f"{pipeline_task_id}.json"),
            agent_result_ref=str(agent_result_path) if agent_result is not None else None,
        )

        if record.use_viz:
            self._set(record, progress_msg=_PROGRESS["viz"])
            try:
                from core.visualization import (
                    render_app_pie,
                    render_app_service_sankey,
                    render_service_type_bar,
                )

                viz_paths = {
                    "pie": render_app_pie(final_report, output_dir / "app_pie.html"),
                    "bar": render_service_type_bar(final_report, output_dir / "service_type_bar.html"),
                    "sankey": render_app_service_sankey(
                        final_report, output_dir / "app_service_sankey.html"
                    ),
                }
                final_report["artifacts"]["viz"] = viz_paths
            except Exception as exc:  # noqa: BLE001
                logger.exception("viz stage failed: %s", exc)
                final_report.setdefault("errors", []).append(f"viz: {exc}")

        with final_report_path.open("w", encoding="utf-8") as handle:
            json.dump(final_report, handle, ensure_ascii=False, indent=2)

        new_session_files = sorted(_snapshot_dir(sessions_dir) - before_session_files)
        input_files = sorted(
            str(path)
            for path in (AGENT_WORKSPACE_DIR / "inputs").glob(f"{pipeline_task_id}_chunk_*.json")
        )
        output_files = sorted(
            str(path)
            for path in (AGENT_WORKSPACE_DIR / "outputs").glob(f"{pipeline_task_id}_chunk_*_result.json")
        )

        self._set(
            record,
            status="success",
            progress_msg=_PROGRESS["done"],
            final_report=final_report,
            final_report_path=final_report_path,
            session_paths=new_session_files,
            input_paths=input_files,
            output_paths=output_files,
            finished_at=time.time(),
        )


def _snapshot_dir(directory: Path) -> set[str]:
    if not directory.is_dir():
        return set()
    return {str(p.resolve()) for p in directory.glob("*.jsonl")}


registry = TaskRegistry()
