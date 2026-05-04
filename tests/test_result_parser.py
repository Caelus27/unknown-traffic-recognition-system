"""单元测试：core.agent.result_parser。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent.result_parser import parse_agent_outputs


def _write(tmp_path: Path, name: str, payload) -> Path:
    file_path = tmp_path / name
    file_path.write_text(json.dumps(payload), encoding="utf-8")
    return file_path


def test_parse_valid_decision(tmp_path):
    payload = {
        "schema_version": "agent_result/v1",
        "decisions": [
            {
                "flow_key": "tcp:1.1.1.1:1234<->2.2.2.2:443",
                "final_label": "gmail:web",
                "app": "gmail",
                "service_type": "web",
                "confidence": 0.92,
                "reason": "SNI 命中",
                "evidence": [{"source": "sni", "value": "smtp.googlemail.com", "weight": 0.9}],
            }
        ],
    }
    path = _write(tmp_path, "out.json", payload)
    result = parse_agent_outputs([path], pcap_name="x.pcap")
    assert result["schema_version"] == "agent_result/v1"
    assert len(result["decisions"]) == 1
    d = result["decisions"][0]
    assert d["app"] == "gmail"
    assert d["service_type"] == "web"
    assert 0.0 <= d["confidence"] <= 1.0
    assert d["evidence"][0]["source"] == "sni"


def test_invalid_service_type_is_dropped(tmp_path):
    payload = {
        "decisions": [
            {
                "flow_key": "tcp:a:1<->b:2",
                "app": "x",
                "service_type": "email",  # 不在词表里
                "final_label": "x:email",
                "confidence": 0.5,
            }
        ]
    }
    path = _write(tmp_path, "out.json", payload)
    result = parse_agent_outputs([path])
    d = result["decisions"][0]
    assert d["service_type"] is None
    assert d["final_label"] is None


def test_confidence_clamped(tmp_path):
    payload = {
        "decisions": [
            {"flow_key": "tcp:a:1<->b:2", "app": "x", "service_type": "web", "confidence": 1.7}
        ]
    }
    path = _write(tmp_path, "out.json", payload)
    result = parse_agent_outputs([path])
    assert result["decisions"][0]["confidence"] == 1.0


def test_split_final_label_into_app_service(tmp_path):
    payload = {
        "decisions": [
            {"flow_key": "tcp:a:1<->b:2", "final_label": "bilibili:stream", "confidence": 0.7}
        ]
    }
    path = _write(tmp_path, "out.json", payload)
    d = parse_agent_outputs([path])["decisions"][0]
    assert d["app"] == "bilibili"
    assert d["service_type"] == "stream"


def test_missing_file_records_error(tmp_path):
    result = parse_agent_outputs([tmp_path / "nope.json"])
    assert result["decisions"] == []
    assert any("missing" in err for err in result["errors"])


def test_dedupe_by_flow_key(tmp_path):
    payload = {
        "decisions": [
            {"flow_key": "tcp:a:1<->b:2", "app": "x", "service_type": "web", "confidence": 0.5},
            {"flow_key": "tcp:a:1<->b:2", "app": "y", "service_type": "stream", "confidence": 0.6},
        ]
    }
    path = _write(tmp_path, "out.json", payload)
    result = parse_agent_outputs([path])
    assert len(result["decisions"]) == 1
    assert result["decisions"][0]["app"] == "x"
