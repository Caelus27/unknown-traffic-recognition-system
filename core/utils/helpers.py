from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any


COMMON_SECOND_LEVEL_SUFFIXES = {"ac", "co", "com", "edu", "gov", "net", "org"}

SERVICE_TYPE_KEYWORDS = {
    "video": {"video", "stream", "movie", "tv", "watch"},
    "audio": {"audio", "music", "spotify", "podcast"},
    "email": {"imap", "smtp", "mail", "email", "pop3", "pop"},
    "chat": {"chat", "message", "messaging", "voip", "sip"},
    "file": {"download", "upload", "file", "sync", "storage", "backup"},
    "news": {"news", "headline", "article"},
    "control": {"dns", "control", "management", "device", "telemetry", "update"},
    "web": {"http", "https", "web", "browser", "site", "page"},
}

SERVICE_PORT_HINTS = {
    53: "control",
    80: "web",
    110: "email",
    143: "email",
    443: "web",
    465: "email",
    587: "email",
    993: "email",
    995: "email",
    1935: "video",
}


def normalize_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text == "" or text in {"-", "(empty)", "None", "nan"}:
        return None
    return text


def normalize_domain(value: Any) -> str | None:
    text = normalize_text(value)
    if not text:
        return None
    return text.strip(".").lower()


def safe_int(value: Any) -> int | None:
    text = normalize_text(value)
    if text is None:
        return None
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def safe_float(value: Any) -> float | None:
    text = normalize_text(value)
    if text is None:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def build_exact_flow_tuple(
    src_ip: Any,
    src_port: Any,
    dst_ip: Any,
    dst_port: Any,
    transport: Any,
) -> tuple[str, int, str, int, str]:
    return (
        normalize_text(src_ip) or "",
        safe_int(src_port) or 0,
        normalize_text(dst_ip) or "",
        safe_int(dst_port) or 0,
        (normalize_text(transport) or "unknown").lower(),
    )


def build_canonical_flow_tuple(
    src_ip: Any,
    src_port: Any,
    dst_ip: Any,
    dst_port: Any,
    transport: Any,
) -> tuple[str, str]:
    transport_value = (normalize_text(transport) or "unknown").lower()
    endpoints = sorted(
        [
            f"{normalize_text(src_ip) or ''}:{safe_int(src_port) or 0}",
            f"{normalize_text(dst_ip) or ''}:{safe_int(dst_port) or 0}",
        ]
    )
    return transport_value, "<->".join(endpoints)


def make_flow_key(
    src_ip: Any,
    src_port: Any,
    dst_ip: Any,
    dst_port: Any,
    transport: Any,
) -> str:
    proto, endpoints = build_canonical_flow_tuple(src_ip, src_port, dst_ip, dst_port, transport)
    return f"{proto}:{endpoints}"


def parse_zeek_vector(value: Any) -> list[str]:
    text = normalize_text(value)
    if not text:
        return []
    stripped = text.strip("[]")
    if stripped == "":
        return []
    if stripped.startswith("{") and stripped.endswith("}"):
        stripped = stripped[1:-1]
    return [item.strip() for item in stripped.split(",") if item.strip()]


def extract_domain_brand(host: Any) -> str | None:
    domain = normalize_domain(host)
    if not domain:
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    labels = [label for label in domain.split(".") if label]
    if len(labels) == 1:
        return labels[0]
    if len(labels) >= 3 and labels[-2] in COMMON_SECOND_LEVEL_SUFFIXES:
        return labels[-3]
    return labels[-2]


def infer_service_type_from_port(port: int | None) -> str | None:
    if port is None:
        return None
    return SERVICE_PORT_HINTS.get(port)


def infer_service_type_from_text(*values: Any) -> str | None:
    tokens: set[str] = set()
    for value in values:
        text = normalize_text(value)
        if not text:
            continue
        tokens.update(re.findall(r"[a-z0-9_]+", text.lower()))
    for service_type, keywords in SERVICE_TYPE_KEYWORDS.items():
        if tokens & keywords:
            return service_type
    return None


def classify_ip_scope(ip_value: Any) -> str:
    text = normalize_text(ip_value)
    if not text:
        return "unknown"
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    return "global"


def is_broadcast_or_multicast(ip_value: Any) -> bool:
    text = normalize_text(ip_value)
    if text == "255.255.255.255":
        return True
    return classify_ip_scope(text) in {"multicast", "link_local"}


def load_json_file(path: str | Path, default: Any = None) -> Any:
    json_path = Path(path)
    if not json_path.exists():
        return default
    with json_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_json_file(path: str | Path, payload: Any) -> None:
    json_path = Path(path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def load_markdown_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:
        return {}, text
    frontmatter_text = parts[0][4:]
    body = parts[1]
    metadata: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in frontmatter_text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if re.match(r"^[A-Za-z0-9_\-]+:\s*", line):
            key, raw_value = line.split(":", 1)
            key = key.strip().replace("-", "_")
            value = raw_value.strip()
            if value.startswith("[") and value.endswith("]"):
                inner = value[1:-1].strip()
                metadata[key] = [item.strip().strip("'\"") for item in inner.split(",") if item.strip()]
            elif value == "":
                metadata[key] = []
            else:
                metadata[key] = value.strip("'\"")
            current_key = key
        elif line.lstrip().startswith("- ") and current_key:
            metadata.setdefault(current_key, [])
            metadata[current_key].append(line.split("- ", 1)[1].strip().strip("'\""))
    return metadata, body
