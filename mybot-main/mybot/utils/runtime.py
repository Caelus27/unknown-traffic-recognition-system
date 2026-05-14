"""Runtime-specific helper functions and constants."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from mybot.utils.helpers import stringify_text_blocks

_MAX_REPEAT_EXTERNAL_LOOKUPS = 2
_MAX_PER_TARGET_LOOKUPS = 2  # 跨 web_fetch / web_search / whois / dns_* / mcp_* 合计

# 共享 target 预算的内置工具集合：对同一 target（域名 / URL host / IP）的合计调用数受限
_TARGET_BUDGET_TOOLS = {
    "web_fetch",
    "web_search",
    "whois_lookup",
    "dns_records",
    "dns_health_check",
    "domain_analysis",
}
# 仅接受域名、不接受 IP 字面量的工具
_DOMAIN_ONLY_TOOLS = {
    "whois_lookup",
    "dns_records",
    "dns_health_check",
    "domain_analysis",
}
# MCP 工具子串识别（mybot 给 MCP 工具加 "mcp_<server>_<tool>" 前缀）
# - mcp_*ip2location* 取 ip 参数；
# - mcp_*firecrawl_search 取 query；
# - 其它 mcp_*firecrawl_* 取 url。
_MCP_IP_LOOKUP_SUBSTRINGS = ("ip2location",)
_MCP_FIRECRAWL_SEARCH_SUBSTRINGS = ("firecrawl_search",)
_MCP_URL_LOOKUP_SUBSTRINGS = (
    "firecrawl_scrape",
    "firecrawl_crawl",
    "firecrawl_map",
    "firecrawl_extract",
    "firecrawl_parse",
)

EMPTY_FINAL_RESPONSE_MESSAGE = (
    "I completed the tool steps but couldn't produce a final answer. "
    "Please try again or narrow the task."
)

FINALIZATION_RETRY_PROMPT = (
    "Please provide your response to the user based on the conversation above."
)

LENGTH_RECOVERY_PROMPT = (
    "Output limit reached. Continue exactly where you left off "
    "— no recap, no apology. Break remaining work into smaller steps if needed."
)


def empty_tool_result_message(tool_name: str) -> str:
    """Short prompt-safe marker for tools that completed without visible output."""
    return f"({tool_name} completed with no output)"


def ensure_nonempty_tool_result(tool_name: str, content: Any) -> Any:
    """Replace semantically empty tool results with a short marker string."""
    if content is None:
        return empty_tool_result_message(tool_name)
    if isinstance(content, str) and not content.strip():
        return empty_tool_result_message(tool_name)
    if isinstance(content, list):
        if not content:
            return empty_tool_result_message(tool_name)
        text_payload = stringify_text_blocks(content)
        if text_payload is not None and not text_payload.strip():
            return empty_tool_result_message(tool_name)
    return content


def is_blank_text(content: str | None) -> bool:
    """True when *content* is missing or only whitespace."""
    return content is None or not content.strip()


def build_finalization_retry_message() -> dict[str, str]:
    """A short no-tools-allowed prompt for final answer recovery."""
    return {"role": "user", "content": FINALIZATION_RETRY_PROMPT}


def build_length_recovery_message() -> dict[str, str]:
    """Prompt the model to continue after hitting output token limit."""
    return {"role": "user", "content": LENGTH_RECOVERY_PROMPT}


def external_lookup_signature(tool_name: str, arguments: dict[str, Any]) -> str | None:
    """Stable signature for repeated external lookups we want to throttle."""
    if tool_name == "web_fetch":
        url = str(arguments.get("url") or "").strip()
        if url:
            return f"web_fetch:{url.lower()}"
    if tool_name == "web_search":
        query = str(arguments.get("query") or arguments.get("search_term") or "").strip()
        if query:
            return f"web_search:{query.lower()}"
    if tool_name in _DOMAIN_ONLY_TOOLS:
        domain = str(arguments.get("domain") or "").strip()
        if domain:
            return f"{tool_name}:{domain.lower()}"
    # MCP-namespaced tools
    if _matches_mcp(tool_name, _MCP_IP_LOOKUP_SUBSTRINGS):
        ip_arg = str(arguments.get("ip") or arguments.get("ip_address") or "").strip()
        if ip_arg:
            return f"{tool_name}:{ip_arg.lower()}"
    if _matches_mcp(tool_name, _MCP_FIRECRAWL_SEARCH_SUBSTRINGS):
        q = str(arguments.get("query") or arguments.get("search_term") or "").strip()
        if q:
            return f"{tool_name}:{q.lower()}"
    if _matches_mcp(tool_name, _MCP_URL_LOOKUP_SUBSTRINGS):
        url = str(arguments.get("url") or "").strip()
        if url:
            return f"{tool_name}:{url.lower()}"
    return None


def _matches_mcp(tool_name: str, substrings: tuple[str, ...]) -> bool:
    if not tool_name.startswith("mcp_"):
        return False
    lowered = tool_name.lower()
    return any(s in lowered for s in substrings)


def _is_ip_literal(host: str) -> bool:
    if not host:
        return False
    h = host.strip().strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _extract_target(tool_name: str, arguments: dict[str, Any]) -> str | None:
    """提取调用所瞄准的"目标"，用于跨工具的 per-target 预算计数。

    web_fetch / mcp_firecrawl_scrape → URL 的 hostname；
    web_search / mcp_firecrawl_search → 整段查询；
    whois/dns/domain_analysis → domain；
    mcp_ip2location_* → IP。
    """
    if tool_name == "web_fetch" or _matches_mcp(tool_name, _MCP_URL_LOOKUP_SUBSTRINGS):
        url = str(arguments.get("url") or "").strip()
        if not url:
            return None
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        return host or None
    if tool_name == "web_search" or _matches_mcp(tool_name, _MCP_FIRECRAWL_SEARCH_SUBSTRINGS):
        q = str(arguments.get("query") or arguments.get("search_term") or "").strip().lower()
        return q or None
    if tool_name in _DOMAIN_ONLY_TOOLS:
        d = str(arguments.get("domain") or "").strip().lower()
        return d or None
    if _matches_mcp(tool_name, _MCP_IP_LOOKUP_SUBSTRINGS):
        ip_arg = str(arguments.get("ip") or arguments.get("ip_address") or "").strip().lower()
        return ip_arg or None
    return None


def repeated_external_lookup_error(
    tool_name: str,
    arguments: dict[str, Any],
    seen_counts: dict[str, int],
) -> str | None:
    """Block repeated / out-of-budget / IP-as-domain external lookups.

    Three checks (first match wins, all return a synthetic error string):

    1. Domain-only tool (whois_lookup / dns_*) called with an IP literal.
       The agent should use IP-aware tools (e.g. web_fetch) instead — reject
       up-front to save tokens.
    2. Same exact (tool + arg) repeated more than `_MAX_REPEAT_EXTERNAL_LOOKUPS`.
    3. Combined per-target calls across the whole tool family exceed
       `_MAX_PER_TARGET_LOOKUPS`. Targets share a counter under the
       prefix `target:<host>`.
    """

    # (1) IP-as-domain rejection
    if tool_name in _DOMAIN_ONLY_TOOLS:
        domain = str(arguments.get("domain") or "").strip().strip("[]")
        if domain and _is_ip_literal(domain):
            logger.warning(
                "Blocking {} called with IP literal '{}'", tool_name, domain
            )
            return (
                f"Error: tool '{tool_name}' only accepts domain names, not IP addresses. "
                f"Got '{domain}'. If you only have an IP, use web_fetch with https://<ip>/ "
                f"or skip this lookup — do not fabricate a domain."
            )

    # (1b) MCP ip2location-style tools: only accept ONE valid IP per call
    if _matches_mcp(tool_name, _MCP_IP_LOOKUP_SUBSTRINGS):
        ip_arg = str(arguments.get("ip") or arguments.get("ip_address") or "").strip().strip("[]")
        if not ip_arg:
            return (
                f"Error: tool '{tool_name}' requires the 'ip' argument with a single IP address."
            )
        if not _is_ip_literal(ip_arg):
            logger.warning(
                "Blocking {} called with malformed ip arg '{}'", tool_name, ip_arg[:120]
            )
            return (
                f"Error: tool '{tool_name}' got ip='{ip_arg[:120]}', which is not a single valid IP. "
                f"Pass exactly one IPv4 or IPv6 address per call (do NOT comma-join multiple IPs). "
                f"Issue one tool call per IP if you need to query several."
            )

    # (2) per-(tool,arg) repeat throttle
    signature = external_lookup_signature(tool_name, arguments)
    if signature is not None:
        count = seen_counts.get(signature, 0) + 1
        seen_counts[signature] = count
        if count > _MAX_REPEAT_EXTERNAL_LOOKUPS:
            logger.warning(
                "Blocking repeated external lookup {} on attempt {}",
                signature[:160],
                count,
            )
            return (
                "Error: repeated external lookup blocked. "
                "Use the results you already have to answer, or try a meaningfully different source."
            )

    # (3) combined per-target budget across web_fetch / web_search / whois / dns_* / mcp_*
    is_mcp_target_tool = tool_name.startswith("mcp_") and (
        _matches_mcp(tool_name, _MCP_IP_LOOKUP_SUBSTRINGS)
        or _matches_mcp(tool_name, _MCP_FIRECRAWL_SEARCH_SUBSTRINGS)
        or _matches_mcp(tool_name, _MCP_URL_LOOKUP_SUBSTRINGS)
    )
    if tool_name in _TARGET_BUDGET_TOOLS or is_mcp_target_tool:
        target = _extract_target(tool_name, arguments)
        if target:
            target_key = f"target:{target}"
            target_count = seen_counts.get(target_key, 0) + 1
            seen_counts[target_key] = target_count
            if target_count > _MAX_PER_TARGET_LOOKUPS:
                logger.warning(
                    "Blocking lookup over per-target budget: target={} count={}",
                    target[:160],
                    target_count,
                )
                return (
                    f"Error: per-target lookup budget exhausted ({_MAX_PER_TARGET_LOOKUPS} calls "
                    f"already made for '{target}' across web_fetch/web_search/whois/dns_*). "
                    f"Move on with the evidence already gathered or pick a different target."
                )

    return None
