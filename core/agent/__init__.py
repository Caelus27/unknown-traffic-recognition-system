"""模块B：Agent 智能挖掘对外接口。"""

from __future__ import annotations

from core.agent.input_builder import build_agent_input
from core.agent.result_parser import parse_agent_outputs
from core.agent.runner import run_agent, run_agent_sync
from core.agent.schema import (
    AgentDecision,
    AgentEvidence,
    AgentInputJob,
    AgentResult,
    SERVICE_TYPE_VOCAB,
)

__all__ = [
    "AgentDecision",
    "AgentEvidence",
    "AgentInputJob",
    "AgentResult",
    "SERVICE_TYPE_VOCAB",
    "build_agent_input",
    "parse_agent_outputs",
    "run_agent",
    "run_agent_sync",
]
