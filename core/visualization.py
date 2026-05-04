"""模块C 可视化：Plotly 三图（饼图/柱状图/Sankey）。

Plotly 缺失时函数返回 None 并打印 warning，不阻塞主流程。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _import_plotly():
    try:
        import plotly.graph_objects as go  # type: ignore
        return go
    except ImportError:
        logger.warning("Plotly 未安装，可视化跳过；可运行 `pip install plotly` 启用。")
        return None


def render_app_pie(report: dict[str, Any], output_path: str | Path) -> str | None:
    go = _import_plotly()
    if go is None:
        return None
    by_app = (report.get("aggregations") or {}).get("by_app") or {}
    if not by_app:
        return None

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fig = go.Figure(
        data=[
            go.Pie(
                labels=list(by_app.keys()),
                values=list(by_app.values()),
                hole=0.35,
            )
        ]
    )
    fig.update_layout(
        title=f"应用层占比 — {report.get('pcap_name') or ''}",
        legend_orientation="v",
    )
    fig.write_html(str(output_path), include_plotlyjs="cdn")
    return str(output_path)


def render_service_type_bar(report: dict[str, Any], output_path: str | Path) -> str | None:
    go = _import_plotly()
    if go is None:
        return None
    by_service = (report.get("aggregations") or {}).get("by_service_type") or {}
    if not by_service:
        return None

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    labels = list(by_service.keys())
    values = list(by_service.values())
    fig = go.Figure(data=[go.Bar(x=labels, y=values)])
    fig.update_layout(
        title=f"服务类型层占比 — {report.get('pcap_name') or ''}",
        xaxis_title="service_type",
        yaxis_title="flow count",
    )
    fig.write_html(str(output_path), include_plotlyjs="cdn")
    return str(output_path)


def render_app_service_sankey(report: dict[str, Any], output_path: str | Path) -> str | None:
    go = _import_plotly()
    if go is None:
        return None
    pairs = (report.get("aggregations") or {}).get("app_to_service_type") or []
    if not pairs:
        return None

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    apps = sorted({item["app"] for item in pairs})
    services = sorted({item["service_type"] for item in pairs})
    nodes = apps + services
    node_index = {name: idx for idx, name in enumerate(nodes)}

    sources = [node_index[item["app"]] for item in pairs]
    targets = [node_index[item["service_type"]] + len(apps) for item in pairs]
    values = [item["count"] for item in pairs]

    fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(label=nodes, pad=15, thickness=18),
                link=dict(source=sources, target=targets, value=values),
            )
        ]
    )
    fig.update_layout(title=f"应用-服务关系 — {report.get('pcap_name') or ''}")
    fig.write_html(str(output_path), include_plotlyjs="cdn")
    return str(output_path)
