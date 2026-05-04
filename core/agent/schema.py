"""模块B 数据契约：AgentInputJob/v1 与 AgentResult/v1。"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# 与 classifier_model/run_classifier_infer.py 的 LABEL_NAMES 对齐。
SERVICE_TYPE_VOCAB: tuple[str, ...] = (
    "bulk-transfer",
    "interactive",
    "stream",
    "vpn",
    "web",
)


class _Base(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class AgentEvidence(_Base):
    source: str
    value: Any | None = None
    weight: float | None = None


class AgentDecision(_Base):
    flow_key: str
    final_label: str | None = None
    app: str | None = None
    service_type: Literal[
        "bulk-transfer",
        "interactive",
        "stream",
        "vpn",
        "web",
    ] | None = None
    confidence: float | None = None
    reason: str | None = None
    evidence: list[AgentEvidence] = Field(default_factory=list)
    tool_trace: dict[str, Any] = Field(default_factory=dict)


class AgentInputJob(_Base):
    schema_version: Literal["agent_input/v1"] = "agent_input/v1"
    job: dict[str, Any]


class AgentResult(_Base):
    schema_version: Literal["agent_result/v1"] = "agent_result/v1"
    pcap_name: str | None = None
    timestamp: str | None = None
    decisions: list[AgentDecision] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
