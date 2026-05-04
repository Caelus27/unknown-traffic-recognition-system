"""单元测试：core.merge.build_final_report。"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.merge import build_final_report


def _preprocess_fixture():
    return {
        "schema_version": "preprocess/v1",
        "pcap_name": "demo.pcap",
        "timestamp": "2026-05-04T01:00:00Z",
        "stats": {"total_flows": 3, "known_count": 1, "unknown_count": 2, "known_ratio": 33.33},
        "known": [
            {"flow_key": "udp:1.1.1.1:53<->2.2.2.2:53", "label": "system:dns"},
        ],
        "unknown": [
            {"flow_key": "tcp:a:1<->b:2"},
            {"flow_key": "tcp:c:3<->d:4"},
        ],
    }


def test_aggregations_count_known_and_agent_labeled():
    preprocess_result = _preprocess_fixture()
    agent_result = {
        "schema_version": "agent_result/v1",
        "decisions": [
            {
                "flow_key": "tcp:a:1<->b:2",
                "final_label": "bilibili:stream",
                "app": "bilibili",
                "service_type": "stream",
                "confidence": 0.7,
                "reason": "SNI bilibili.com",
                "evidence": [],
            }
        ],
    }
    report = build_final_report(preprocess_result, agent_result)

    assert report["schema_version"] == "final_report/v1"
    assert report["stats"]["agent_labeled_count"] == 1

    by_app = report["aggregations"]["by_app"]
    assert by_app.get("system") == 1
    assert by_app.get("bilibili") == 1
    assert by_app.get("unknown_app") == 1

    by_service = report["aggregations"]["by_service_type"]
    assert by_service.get("dns") == 1
    assert by_service.get("stream") == 1
    assert by_service.get("unknown") == 1


def test_unlabeled_unknown_marked_skipped():
    preprocess_result = _preprocess_fixture()
    report = build_final_report(preprocess_result, agent_result=None)

    assert report["stats"]["agent_labeled_count"] == 0
    for flow in report["unknown_labeled"]:
        assert flow["final_label"] is None
        assert flow["reason"] == "agent_skipped"


def test_artifacts_refs_passthrough():
    preprocess_result = _preprocess_fixture()
    report = build_final_report(
        preprocess_result,
        agent_result=None,
        preprocess_result_ref="data/processed/results/demo.json",
        agent_result_ref="agent_workspace/outputs/demo_agent_result.json",
    )
    assert report["artifacts"]["preprocess_result_ref"] == "data/processed/results/demo.json"
    assert report["artifacts"]["agent_result_ref"] == "agent_workspace/outputs/demo_agent_result.json"
    assert report["artifacts"]["viz"] == {"pie": None, "bar": None, "sankey": None}
