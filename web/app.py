"""FastAPI 应用：上传 PCAP → 异步运行流水线 → 返回 dashboard / 流详情。"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from web.reporting import build_flow_detail, to_dashboard
from web.security import (
    MAX_PCAP_BYTES,
    UploadValidationError,
    safe_display_name,
    validate_extension,
    validate_magic,
)
from web.tasks import UPLOAD_DIR, registry

logger = logging.getLogger("web.app")

app = FastAPI(title="未知流量识别 Web", docs_url="/api/docs", redoc_url=None)

_STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/static/index.html")


@app.post("/api/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    skip_agent: bool = Form(False),
    enable_viz: bool = Form(False),
    max_flows_per_chunk: int = Form(25),
):
    try:
        validate_extension(file.filename)
    except UploadValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from None

    display_name = safe_display_name(file.filename)
    upload_path = UPLOAD_DIR / f"{uuid.uuid4().hex}.pcap"

    bytes_written = 0
    try:
        with upload_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_PCAP_BYTES:
                    out.close()
                    upload_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"file too large; limit is {MAX_PCAP_BYTES} bytes",
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        upload_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"upload failed: {exc}") from None
    finally:
        await file.close()

    if bytes_written == 0:
        upload_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="empty upload")

    try:
        validate_magic(upload_path)
    except UploadValidationError as exc:
        upload_path.unlink(missing_ok=True)
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from None

    record = registry.create(
        upload_path=upload_path,
        display_name=display_name,
        use_agent=not skip_agent,
        use_viz=enable_viz,
        max_flows_per_chunk=max_flows_per_chunk,
    )
    registry.submit(record)

    return JSONResponse(
        {
            "task_id": record.task_id,
            "status": record.status,
            "display_name": record.display_name,
            "size_bytes": bytes_written,
        }
    )


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str):
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail="task not found")
    payload = record.to_public()
    if record.status == "success" and record.final_report is not None:
        payload["dashboard"] = to_dashboard(record.final_report)
    return payload


@app.get("/api/tasks/{task_id}/raw")
def get_task_raw(task_id: str):
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail="task not found")
    if record.status != "success" or record.final_report_path is None:
        raise HTTPException(status_code=409, detail=f"task not ready: {record.status}")
    return FileResponse(str(record.final_report_path), media_type="application/json")


@app.get("/api/tasks/{task_id}/flows/{flow_key:path}")
def get_flow_detail(task_id: str, flow_key: str):
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail="task not found")
    if record.status != "success" or record.final_report is None:
        raise HTTPException(status_code=409, detail=f"task not ready: {record.status}")

    detail = build_flow_detail(
        record.final_report,
        flow_key,
        session_paths=[Path(p) for p in record.session_paths],
        input_paths=[Path(p) for p in record.input_paths],
    )
    if detail is None:
        raise HTTPException(status_code=404, detail="flow not found in unknown_labeled")

    detail["task_id"] = task_id
    return detail
