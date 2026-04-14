"""Message bus module for decoupled channel-agent communication."""

from mybot.bus.events import InboundMessage, OutboundMessage
from mybot.bus.queue import MessageBus

__all__ = ["MessageBus", "InboundMessage", "OutboundMessage"]
