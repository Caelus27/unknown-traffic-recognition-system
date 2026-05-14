"""Domain analysis tools: WHOIS, DNS records, DNS health.

These tools were originally exposed by the standalone ``domain-tools-mcp-server``
project. They are now built into mybot as first-class internal tools so the
agent can analyse domains without spinning up an external MCP process.

All blocking I/O (``dnspython`` resolution, ``python-whois`` lookups) is
offloaded to a worker thread via :func:`asyncio.to_thread` to keep the agent
loop responsive.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from mybot.agent.tools.base import Tool, tool_parameters
from mybot.agent.tools.schema import ArraySchema, StringSchema, tool_parameters_schema


_DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
_ALLOWED_RECORD_TYPES: frozenset[str] = frozenset(
    ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA")
)


def _missing_dep_error(pkg: str) -> str:
    return (
        f"Error: required dependency '{pkg}' is not installed. "
        f"Run `pip install {pkg}` to enable this tool."
    )


def _normalize_domain(domain: str) -> str:
    """Strip scheme/path/port, lowercase. Returns the bare host label."""
    if not isinstance(domain, str):
        raise ValueError("domain must be a string")
    value = domain.strip()
    if not value:
        raise ValueError("domain is empty")
    if "://" in value:
        value = urlparse(value).netloc or value.split("/")[0]
    # Drop optional path / port / userinfo
    value = value.split("/", 1)[0]
    if "@" in value:
        value = value.split("@", 1)[-1]
    if value.startswith("["):  # IPv6 literal — drop brackets
        value = value.strip("[]")
    elif ":" in value and value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.lower().rstrip(".")


def _format_date(date_obj: Any) -> str:
    """Mirror domain-tools-mcp-server formatting: ISO string or 'N/A'."""
    if date_obj is None:
        return "N/A"
    if isinstance(date_obj, list):
        date_obj = date_obj[0] if date_obj else None
    if date_obj is None:
        return "N/A"
    try:
        if isinstance(date_obj, datetime):
            return date_obj.isoformat()
        return str(date_obj)
    except Exception:
        return "N/A"


def _make_resolver():
    """Build a configured dns.resolver.Resolver respecting env overrides."""
    import dns.resolver  # local import — optional dep

    resolver = dns.resolver.Resolver()
    timeout_env = os.environ.get("DNS_TIMEOUT")
    lifetime_env = os.environ.get("DNS_LIFETIME")
    try:
        if timeout_env:
            resolver.timeout = float(timeout_env)
    except ValueError:
        pass
    try:
        if lifetime_env:
            resolver.lifetime = float(lifetime_env)
    except ValueError:
        pass
    return resolver


# ---------------------------------------------------------------------------
# whois_lookup
# ---------------------------------------------------------------------------


@tool_parameters(
    tool_parameters_schema(
        domain=StringSchema(
            "Domain name to lookup (e.g. example.com). URLs are accepted; the "
            "scheme/path are stripped automatically.",
            min_length=1,
        ),
        required=["domain"],
    )
)
class WhoisLookupTool(Tool):
    """Fetch WHOIS registration data for a domain."""

    name = "whois_lookup"
    description = (
        "Get WHOIS information (registrar, creation/expiry dates, name servers, "
        "registrant org/country) for a domain. Useful for cert/ip evidence when "
        "classifying unknown traffic."
    )

    @property
    def read_only(self) -> bool:
        return True

    async def execute(self, domain: str, **kwargs: Any) -> str:
        try:
            host = _normalize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"

        try:
            import whois  # type: ignore[import-untyped]
        except ImportError:
            return _missing_dep_error("python-whois")

        try:
            w = await asyncio.to_thread(whois.whois, host)
        except Exception as e:
            logger.debug("WHOIS lookup failed for {}: {}", host, e)
            return f"Error performing WHOIS lookup for {host}: {e}"

        data: dict[str, Any] = {
            "domain": host,
            "registrar": getattr(w, "registrar", "N/A"),
            "creation_date": _format_date(getattr(w, "creation_date", None)),
            "expiration_date": _format_date(getattr(w, "expiration_date", None)),
            "updated_date": _format_date(getattr(w, "updated_date", None)),
            "status": getattr(w, "status", "N/A"),
            "name_servers": getattr(w, "name_servers", []),
            "registrant_country": getattr(w, "country", "N/A"),
            "registrant_org": getattr(w, "org", "N/A"),
        }
        if data["expiration_date"] != "N/A":
            try:
                exp_iso = data["expiration_date"].replace("Z", "+00:00")
                exp_date = datetime.fromisoformat(exp_iso)
                if exp_date.tzinfo is None:
                    exp_date = exp_date.replace(tzinfo=timezone.utc)
                data["days_until_expiry"] = (exp_date - datetime.now(timezone.utc)).days
            except Exception:
                data["days_until_expiry"] = "N/A"

        return f"WHOIS Information for {host}:\n\n" + json.dumps(
            data, indent=2, default=str, ensure_ascii=False
        )


# ---------------------------------------------------------------------------
# dns_records
# ---------------------------------------------------------------------------


@tool_parameters(
    tool_parameters_schema(
        domain=StringSchema("Domain name to query.", min_length=1),
        record_types=ArraySchema(
            items=StringSchema(
                "DNS record type",
                enum=list(_ALLOWED_RECORD_TYPES),
            ),
            description=(
                "DNS record types to query. Defaults to "
                "[A, AAAA, MX, NS, TXT, CNAME, SOA] if omitted."
            ),
            min_items=1,
            nullable=True,
        ),
        required=["domain"],
    )
)
class DnsRecordsTool(Tool):
    """Resolve DNS records for a domain."""

    name = "dns_records"
    description = (
        "Query DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA, "
        "PTR, SRV, CAA). Returns a JSON map keyed by record type."
    )

    @property
    def read_only(self) -> bool:
        return True

    async def execute(
        self,
        domain: str,
        record_types: list[str] | None = None,
        **kwargs: Any,
    ) -> str:
        try:
            host = _normalize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"

        try:
            import dns.resolver  # type: ignore[import-untyped]
            import dns.exception  # noqa: F401  # type: ignore[import-untyped]
        except ImportError:
            return _missing_dep_error("dnspython")

        if not record_types:
            record_types = list(_DEFAULT_RECORD_TYPES)
        normalized_types: list[str] = []
        for rt in record_types:
            if not isinstance(rt, str):
                continue
            up = rt.strip().upper()
            if up in _ALLOWED_RECORD_TYPES and up not in normalized_types:
                normalized_types.append(up)
        if not normalized_types:
            return "Error: no valid record types supplied"

        resolver = _make_resolver()
        records_out: dict[str, list[str]] = {}

        def _resolve_one(rtype: str) -> list[str]:
            try:
                answers = resolver.resolve(host, rtype)
            except dns.resolver.NoAnswer:
                return []
            except dns.resolver.NXDOMAIN:
                return ["Domain not found"]
            except Exception as e:  # noqa: BLE001
                return [f"Error: {e}"]
            out: list[str] = []
            for answer in answers:
                if rtype == "MX":
                    out.append(f"{answer.preference} {answer.exchange}")
                elif rtype == "SOA":
                    out.append(f"{answer.mname} {answer.rname} {answer.serial}")
                elif rtype == "TXT":
                    out.append(f'"{answer.to_text()}"')
                else:
                    out.append(str(answer))
            return out

        for rtype in normalized_types:
            records_out[rtype] = await asyncio.to_thread(_resolve_one, rtype)

        payload = {"domain": host, "records": records_out}
        return f"DNS Records for {host}:\n\n" + json.dumps(
            payload, indent=2, ensure_ascii=False
        )


# ---------------------------------------------------------------------------
# dns_health_check
# ---------------------------------------------------------------------------


@tool_parameters(
    tool_parameters_schema(
        domain=StringSchema("Domain name to analyze.", min_length=1),
        required=["domain"],
    )
)
class DnsHealthCheckTool(Tool):
    """Run a battery of DNS sanity checks on a domain."""

    name = "dns_health_check"
    description = (
        "Analyze DNS configuration for common issues (missing A/MX/NS, "
        "redundancy, IPv6, apex CNAME, SOA timing). Returns issues / warnings / "
        "info plus an overall status (HEALTHY / WARNING / CRITICAL)."
    )

    @property
    def read_only(self) -> bool:
        return True

    async def execute(self, domain: str, **kwargs: Any) -> str:
        try:
            host = _normalize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"

        try:
            import dns.resolver  # type: ignore[import-untyped]
        except ImportError:
            return _missing_dep_error("dnspython")

        resolver = _make_resolver()

        def _check() -> dict[str, Any]:
            issues: list[str] = []
            warnings: list[str] = []
            info: list[str] = []

            # A records
            try:
                a_records = resolver.resolve(host, "A")
                a_count = len(a_records)
                info.append(f"Found {a_count} A record(s)")
                if a_count == 0:
                    issues.append("No A records found - domain may not be accessible")
                elif a_count == 1:
                    warnings.append("Only one A record found - consider adding redundancy")
            except dns.resolver.NXDOMAIN:
                issues.append("Domain does not exist (NXDOMAIN)")
            except dns.resolver.NoAnswer:
                issues.append("No A records found - domain may not be accessible")
            except Exception as e:  # noqa: BLE001
                issues.append(f"Error checking A records: {e}")

            # MX records
            try:
                mx_records = resolver.resolve(host, "MX")
                mx_count = len(mx_records)
                info.append(f"Found {mx_count} MX record(s)")
                if mx_count == 1:
                    warnings.append("Only one MX record - consider adding backup MX")
                priorities = [mx.preference for mx in mx_records]
                if len(set(priorities)) != len(priorities):
                    warnings.append("Duplicate MX priorities found")
            except dns.resolver.NoAnswer:
                warnings.append("No MX records configured")
            except dns.resolver.NXDOMAIN:
                pass  # already reported above
            except Exception as e:  # noqa: BLE001
                issues.append(f"Error checking MX records: {e}")

            # NS records
            try:
                ns_records = resolver.resolve(host, "NS")
                ns_count = len(ns_records)
                info.append(f"Found {ns_count} NS record(s)")
                if ns_count < 2:
                    issues.append("Less than 2 NS records - DNS redundancy is insufficient")
                elif ns_count > 13:
                    warnings.append("More than 13 NS records - may cause performance issues")
            except Exception as e:  # noqa: BLE001
                issues.append(f"Error checking NS records: {e}")

            # SOA record
            try:
                soa_records = resolver.resolve(host, "SOA")
                soa = soa_records[0]
                if soa.refresh > 86400:
                    warnings.append("SOA refresh interval is very high (>24h)")
                elif soa.refresh < 300:
                    warnings.append("SOA refresh interval is very low (<5m)")
                if soa.retry > soa.refresh:
                    issues.append("SOA retry interval is greater than refresh interval")
                info.append(f"SOA Serial: {soa.serial}")
            except Exception as e:  # noqa: BLE001
                issues.append(f"Error checking SOA record: {e}")

            # AAAA records
            try:
                aaaa_records = resolver.resolve(host, "AAAA")
                info.append(f"Found {len(aaaa_records)} AAAA record(s) - IPv6 enabled")
            except dns.resolver.NoAnswer:
                warnings.append("No AAAA records found - IPv6 not configured")
            except Exception:
                pass

            # CNAME at apex
            try:
                cname_records = resolver.resolve(host, "CNAME")
                if cname_records:
                    issues.append(
                        "CNAME record found at domain apex - this violates RFC standards"
                    )
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                pass

            return {
                "domain": host,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "issues": issues,
                "warnings": warnings,
                "info": info,
                "overall_status": "CRITICAL"
                if issues
                else ("WARNING" if warnings else "HEALTHY"),
            }

        report = await asyncio.to_thread(_check)
        return f"DNS Health Check for {host}:\n\n" + json.dumps(
            report, indent=2, ensure_ascii=False
        )


# ---------------------------------------------------------------------------
# domain_analysis
# ---------------------------------------------------------------------------


@tool_parameters(
    tool_parameters_schema(
        domain=StringSchema("Domain name to analyze completely.", min_length=1),
        required=["domain"],
    )
)
class DomainAnalysisTool(Tool):
    """One-shot composite of WHOIS + DNS records + DNS health checks."""

    name = "domain_analysis"
    description = (
        "Comprehensive domain analysis: combines WHOIS, full DNS record dump, "
        "and DNS health check into one report. Slower than the individual "
        "tools — call it only when you need the full picture."
    )

    def __init__(self) -> None:
        self._whois = WhoisLookupTool()
        self._records = DnsRecordsTool()
        self._health = DnsHealthCheckTool()

    @property
    def read_only(self) -> bool:
        return True

    async def execute(self, domain: str, **kwargs: Any) -> str:
        try:
            host = _normalize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"

        whois_text, dns_text, health_text = await asyncio.gather(
            self._whois.execute(domain=host),
            self._records.execute(domain=host, record_types=list(_DEFAULT_RECORD_TYPES)),
            self._health.execute(domain=host),
        )

        sep = "=" * 60
        return (
            f"COMPREHENSIVE DOMAIN ANALYSIS FOR: {host}\n{sep}\n\n"
            f"1. WHOIS INFORMATION:\n{whois_text}\n\n"
            f"2. DNS RECORDS:\n{dns_text}\n\n"
            f"3. DNS HEALTH CHECK:\n{health_text}\n\n"
            f"Analysis completed at: {datetime.now(timezone.utc).isoformat()}\n"
        )


__all__ = [
    "WhoisLookupTool",
    "DnsRecordsTool",
    "DnsHealthCheckTool",
    "DomainAnalysisTool",
]
