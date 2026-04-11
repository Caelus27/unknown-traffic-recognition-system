"""Utility helpers shared by preprocessing and agent layers."""

from .helpers import (
    build_canonical_flow_tuple,
    build_exact_flow_tuple,
    classify_ip_scope,
    dump_json_file,
    extract_domain_brand,
    infer_service_type_from_port,
    infer_service_type_from_text,
    is_broadcast_or_multicast,
    load_json_file,
    load_markdown_frontmatter,
    make_flow_key,
    normalize_domain,
    normalize_text,
    parse_zeek_vector,
    safe_float,
    safe_int,
)

__all__ = [
    "build_canonical_flow_tuple",
    "build_exact_flow_tuple",
    "classify_ip_scope",
    "dump_json_file",
    "extract_domain_brand",
    "infer_service_type_from_port",
    "infer_service_type_from_text",
    "is_broadcast_or_multicast",
    "load_json_file",
    "load_markdown_frontmatter",
    "make_flow_key",
    "normalize_domain",
    "normalize_text",
    "parse_zeek_vector",
    "safe_float",
    "safe_int",
]

