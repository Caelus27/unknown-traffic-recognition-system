from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import pandas as pd

from config import (
    CONFIDENCE_THRESHOLD,
    KNOWN_RESULTS_DIR,
    KNOWN_SNI_PATH,
    NDPI_READER,
    PROCESSED_RESULTS_DIR,
    UNKNOWN_FLOWS_DIR,
    UNKNOWN_FLOWS_PCAP_DIR,
)
from core.classifier import apply_classification_results, run_classifier_for_manifest
from core.models import DNSMetadata, FlowMetadata, FlowStats, HTTPMetadata, TLSMetadata
from core.utils import ndpi_utils as ndpi_module
from core.utils.helpers import (
    build_canonical_flow_tuple,
    build_exact_flow_tuple,
    classify_ip_scope,
    dump_json_file,
    extract_domain_brand,
    infer_service_type_from_port,
    is_broadcast_or_multicast,
    make_flow_key,
    normalize_domain,
    normalize_text,
    parse_zeek_vector,
    safe_float,
    safe_int,
)
from core.utils.ndpi_utils import init_ndpi_utils
from core.utils.pcap_utils import create_unknown_flow_pcap_manifest
from core.utils.zeek_utils import extract_traffic_info, run_zeek_on_pcap

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


SYSTEM_PROTOCOL_LABELS = {
    "arp": "system:arp",
    "dhcp": "system:dhcp",
    "dhcpv6": "system:dhcp",
    "dns": "system:dns",
    "icmp": "system:icmp",
    "icmpv6": "system:icmpv6",
    "igmp": "system:igmp",
    "llmnr": "system:llmnr",
    "mdns": "system:mdns",
    "netbios": "system:netbios",
    "netbios.smbv1": "system:file_share",
    "ntp": "system:ntp",
    "service_location_protocol": "system:service_discovery",
    "sip": "system:voip_signal",
    "snmp": "system:snmp",
    "ssdp": "system:ssdp",
    "wsd": "system:device_discovery",
}

NDPI_STRONG_HINT_LABELS = {
    "dropbox": "dropbox:file_sync",
    "spotify": "spotify:audio",
    "pops": "email:email",
}

ENCRYPTED_PROTOCOL_HINTS = {"https", "quic", "ssl", "tls"}
PLAINTEXT_PROTOCOL_HINTS = {"http", "web", "json"}


class TrafficPreprocessor:
    """已知流量过滤核心类（模块A）。"""

    def __init__(self):
        self.known_sni = self._load_known_sni()
        init_ndpi_utils(NDPI_READER)

    def _load_known_sni(self) -> Dict[str, Dict[str, str]]:
        path = Path(KNOWN_SNI_PATH)
        if not path.exists():
            logger.warning("known_sni_list.json 不存在，使用空白名单")
            return {}
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            logger.info("已加载 %s 个已知 SNI", len(data))
            return data
        except Exception as exc:
            logger.error("加载 known_sni_list.json 失败: %s", exc)
            return {}

    def process_pcap(self, pcap_path: str | Path, save_result: bool = True) -> Dict[str, Any]:
        pcap_path = Path(pcap_path)
        timestamp = pd.Timestamp.now().isoformat()
        task_id = f"{pcap_path.stem}_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info("开始处理 PCAP: %s", pcap_path.name)

        zeek_log_dir = run_zeek_on_pcap(pcap_path)
        zeek_info = extract_traffic_info(zeek_log_dir)

        if ndpi_module.ndpi_utils is None:
            raise RuntimeError("nDPI 工具尚未初始化，请先调用 init_ndpi_utils")

        ndpi_csv_path = ndpi_module.ndpi_utils.run_ndpi_on_pcap(pcap_path)
        ndpi_df = ndpi_module.ndpi_utils.parse_ndpi_csv(ndpi_csv_path)
        zeek_indexes = self._build_zeek_indexes(zeek_info)

        known_results: list[dict[str, Any]] = []
        unknown_flows: list[dict[str, Any]] = []

        for _, row in ndpi_df.iterrows():
            flow = self._build_flow_metadata(pcap_path.name, row.to_dict(), zeek_indexes)
            is_known, label, reason = self._classify_flow(flow)
            flow.preprocess_reason = reason
            flow.preprocess_label = label if is_known else None
            flow.confidence = 0.85 if is_known else 0.45

            payload = flow.model_dump(mode="json")
            self._slim_flow_payload(payload)
            payload["reason"] = flow.preprocess_reason
            payload["evidence"] = self._build_preprocess_evidence(flow, is_known)

            if is_known:
                payload["label"] = label
                known_results.append(payload)
            else:
                unknown_flows.append(payload)

        task_dir = UNKNOWN_FLOWS_PCAP_DIR / task_id
        manifest = create_unknown_flow_pcap_manifest(
            pcap_path=pcap_path,
            unknown_flows=unknown_flows,
            task_id=task_id,
            task_dir=task_dir,
            timestamp=timestamp,
        )
        self._apply_pcap_manifest(unknown_flows, manifest)

        manifest_path = Path(manifest.get("manifest_path") or task_dir / "manifest.json")
        classifier_results = run_classifier_for_manifest(manifest_path)
        apply_classification_results(unknown_flows, classifier_results)

        # 将分类模型输出(标签/概率)落到 unknown 结果中。
        # 模型适配器接入前，默认会产生空占位（None）。
        for flow_payload in unknown_flows:
            classification = flow_payload.get("classification_model")
            if isinstance(classification, dict):
                flow_payload["model_label"] = classification.get("label")
                flow_payload["model_probability"] = classification.get("probability")
            else:
                flow_payload["model_label"] = None
                flow_payload["model_probability"] = None
            flow_payload.pop("classification_model", None)

        result = {
            "schema_version": "preprocess/v1",
            "task_id": task_id,
            "pcap_name": pcap_path.name,
            "pcap_path": str(pcap_path),
            "timestamp": timestamp,
            "artifacts": {
                "zeek_log_dir": str(zeek_log_dir),
                "ndpi_csv_path": str(ndpi_csv_path),
                "unknown_flows_pcap_dir": str(task_dir),
                "unknown_flows_manifest": str(manifest_path),
            },
            "stats": {
                "total_flows": len(ndpi_df),
                "known_count": len(known_results),
                "unknown_count": len(unknown_flows),
                "known_ratio": round(len(known_results) / len(ndpi_df) * 100, 2) if len(ndpi_df) > 0 else 0,
            },
            "known": known_results,
            "unknown": unknown_flows,
        }

        if save_result:
            self._save_result_to_json(result, pcap_path)

        logger.info(
            "处理完成！已知: %s | 未知: %s | 已知比例: %s%%",
            len(known_results),
            len(unknown_flows),
            result["stats"]["known_ratio"],
        )
        return self._build_public_result(result)

    def load_result(self, json_path: str | Path) -> Dict[str, Any]:
        path = Path(json_path)
        if not path.exists():
            logger.error("结果文件不存在: %s", path)
            return {}
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:
            logger.error("加载 JSON 失败: %s", exc)
            return {}

    def _save_result_to_json(self, result: Dict[str, Any], pcap_path: Path) -> None:
        base_filename = result.get("task_id") or f"{pcap_path.stem}_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}"

        public = self._build_public_result(result)
        dump_json_file(PROCESSED_RESULTS_DIR / f"{base_filename}.json", public)
        dump_json_file(
            KNOWN_RESULTS_DIR / f"{base_filename}_known.json",
            {
                "pcap_name": public.get("pcap_name"),
                "timestamp": public.get("timestamp"),
                "stats": {
                    "total_flows": public.get("stats", {}).get("total_flows", 0),
                    "known_count": public.get("stats", {}).get("known_count", 0),
                },
                "known": public.get("known", []),
            },
        )
        dump_json_file(
            UNKNOWN_FLOWS_DIR / f"{base_filename}_unknown.json",
            {
                "pcap_name": public.get("pcap_name"),
                "timestamp": public.get("timestamp"),
                "stats": {
                    "total_flows": public.get("stats", {}).get("total_flows", 0),
                    "unknown_count": public.get("stats", {}).get("unknown_count", 0),
                },
                "unknown": public.get("unknown", []),
            },
        )

    @staticmethod
    def _slim_flow_payload(payload: dict[str, Any]) -> None:
        """就地裁剪 flow payload，避免输出过多原始特征/中间产物字段。"""
        for key in ("raw_sources", "unknown_pcap_path", "pcap_extraction", "classification_model"):
            payload.pop(key, None)

        http = payload.get("http")
        if isinstance(http, dict):
            http.pop("raw_records", None)

        dns = payload.get("dns")
        if isinstance(dns, dict):
            dns.pop("raw_records", None)

        tls = payload.get("tls")
        if isinstance(tls, dict):
            tls.pop("raw_ssl_records", None)
            tls.pop("raw_x509_records", None)

    @staticmethod
    def _build_public_result(result: Dict[str, Any]) -> Dict[str, Any]:
        """生成对外输出的精简结果结构（对齐 data/processed/* 20260411 样例）。"""
        return {
            "pcap_name": result.get("pcap_name"),
            "timestamp": result.get("timestamp"),
            "stats": result.get("stats", {}),
            "known": result.get("known", []),
            "unknown": result.get("unknown", []),
        }

    def _apply_pcap_manifest(self, unknown_flows: list[dict[str, Any]], manifest: dict[str, Any]) -> None:
        manifest_flows = manifest.get("flows", [])
        by_flow_key: dict[str, dict[str, Any]] = {}
        for entry in manifest_flows:
            flow_key = normalize_text(entry.get("flow_key"))
            if flow_key:
                by_flow_key[flow_key] = entry

        if len(manifest_flows) != len(unknown_flows):
            logger.warning(
                "unknown_flows 与 manifest.flows 数量不一致: unknown=%s manifest=%s",
                len(unknown_flows),
                len(manifest_flows),
            )

        for index, flow in enumerate(unknown_flows):
            flow_key = normalize_text(flow.get("flow_key"))
            entry = by_flow_key.get(flow_key) if flow_key else None
            if entry is None:
                entry = manifest_flows[index] if index < len(manifest_flows) else None

            if not entry:
                flow["unknown_pcap_index"] = index + 1
                flow["unknown_pcap_path"] = None
                flow["pcap_extraction"] = {
                    "status": "manifest_missing",
                    "error": manifest.get("error"),
                    "packet_count": 0,
                    "byte_count": 0,
                }
                continue

            flow["unknown_pcap_index"] = safe_int(entry.get("index")) or (index + 1)
            flow["unknown_pcap_path"] = entry.get("unknown_pcap_path")
            flow["pcap_extraction"] = entry.get("pcap_extraction") or {
                "status": "unknown",
                "error": None,
                "packet_count": 0,
                "byte_count": 0,
            }

    def _build_zeek_indexes(self, zeek_info: Dict[str, pd.DataFrame]) -> Dict[str, Any]:
        uid_index: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for name in ("conn", "ssl", "http", "dns"):
            df = zeek_info.get(name, pd.DataFrame())
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            if not df.empty and "uid" in df.columns:
                for record in df.to_dict("records"):
                    uid = normalize_text(record.get("uid"))
                    if uid:
                        grouped[uid].append(record)
            uid_index[name] = grouped

        x509_by_fp: dict[str, list[dict[str, Any]]] = defaultdict(list)
        x509_df = zeek_info.get("x509", pd.DataFrame())
        if not x509_df.empty:
            for record in x509_df.to_dict("records"):
                fingerprint = normalize_text(record.get("fingerprint"))
                if fingerprint:
                    x509_by_fp[fingerprint] = x509_by_fp.get(fingerprint, []) + [record]

        exact_conn_index: dict[tuple[str, int, str, int, str], list[dict[str, Any]]] = defaultdict(list)
        canonical_conn_index: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        conn_df = zeek_info.get("conn", pd.DataFrame())
        if not conn_df.empty:
            for record in conn_df.to_dict("records"):
                exact_key = build_exact_flow_tuple(
                    record.get("id.orig_h"),
                    record.get("id.orig_p"),
                    record.get("id.resp_h"),
                    record.get("id.resp_p"),
                    record.get("proto"),
                )
                canonical_key = build_canonical_flow_tuple(
                    record.get("id.orig_h"),
                    record.get("id.orig_p"),
                    record.get("id.resp_h"),
                    record.get("id.resp_p"),
                    record.get("proto"),
                )
                exact_conn_index[exact_key].append(record)
                canonical_conn_index[canonical_key].append(record)

        return {
            "uid": uid_index,
            "x509_by_fp": x509_by_fp,
            "exact_conn_index": exact_conn_index,
            "canonical_conn_index": canonical_conn_index,
        }

    def _build_flow_metadata(
        self,
        pcap_name: str,
        ndpi_row: Dict[str, Any],
        zeek_indexes: Dict[str, Any],
    ) -> FlowMetadata:
        transport = self._infer_transport(ndpi_row)
        src_ip = normalize_text(ndpi_row.get("src_ip")) or "unknown"
        dst_ip = normalize_text(ndpi_row.get("dst_ip")) or "unknown"
        src_port = safe_int(ndpi_row.get("src_port"))
        dst_port = safe_int(ndpi_row.get("dst_port"))
        matched_conn = self._match_zeek_connection(ndpi_row, zeek_indexes, transport)
        matched_uid = normalize_text(matched_conn.get("uid")) if matched_conn else None
        matched_ssl = zeek_indexes["uid"]["ssl"].get(matched_uid, []) if matched_uid else []
        matched_http = zeek_indexes["uid"]["http"].get(matched_uid, []) if matched_uid else []
        matched_dns = zeek_indexes["uid"]["dns"].get(matched_uid, []) if matched_uid else []
        x509_records = self._resolve_x509_records(matched_ssl, zeek_indexes["x509_by_fp"])

        sni = (
            normalize_domain(ndpi_row.get("server_name_sni"))
            or normalize_domain(ndpi_row.get("sni"))
            or self._first_non_empty(record.get("sni") for record in matched_ssl)
            or self._first_non_empty(record.get("server_name") for record in matched_ssl)
            or self._first_non_empty(san for record in x509_records for san in parse_zeek_vector(record.get("san.dns")))
        )
        http = self._build_http_metadata(matched_http)
        dns = self._build_dns_metadata(matched_dns)
        tls = self._build_tls_metadata(ndpi_row, matched_ssl, x509_records, sni)
        is_encrypted = self._is_encrypted_flow(ndpi_row, matched_ssl, tls)

        flow = FlowMetadata(
            flow_id=ndpi_row.get("flow_id"),
            pcap_name=pcap_name,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            transport=transport,
            proto_stack=normalize_text(ndpi_row.get("proto_stack")) or normalize_text(ndpi_row.get("ndpi_proto")),
            ndpi_app=normalize_text(ndpi_row.get("ndpi_app")) or normalize_text(ndpi_row.get("ndpi_proto")),
            is_encrypted=is_encrypted,
            sni=sni,
            http=http,
            dns=dns,
            tls=tls,
            stats=FlowStats(
                start_ts=safe_float(ndpi_row.get("first_seen")) or safe_float(matched_conn.get("ts") if matched_conn else None),
                end_ts=safe_float(ndpi_row.get("last_seen")),
                duration=safe_float(ndpi_row.get("duration")) or safe_float(matched_conn.get("duration") if matched_conn else None),
                total_bytes=(safe_int(ndpi_row.get("c_to_s_bytes")) or 0) + (safe_int(ndpi_row.get("s_to_c_bytes")) or 0),
                c_to_s_bytes=safe_int(ndpi_row.get("c_to_s_bytes")),
                s_to_c_bytes=safe_int(ndpi_row.get("s_to_c_bytes")),
                c_to_s_goodput_bytes=safe_int(ndpi_row.get("c_to_s_goodput_bytes")),
                s_to_c_goodput_bytes=safe_int(ndpi_row.get("s_to_c_goodput_bytes")),
                c_to_s_packets=safe_int(ndpi_row.get("c_to_s_pkts")),
                s_to_c_packets=safe_int(ndpi_row.get("s_to_c_pkts")),
                data_ratio=safe_float(ndpi_row.get("data_ratio")),
                flow_risk=normalize_text(ndpi_row.get("risk")) or normalize_text(ndpi_row.get("flow_risk")),
                packet_length_bins=normalize_text(ndpi_row.get("plen_bins")),
            ),
            preprocess_reason="unclassified",
            raw_sources={
                "ndpi": ndpi_row,
                "zeek_conn": matched_conn or {},
                "zeek_uid": matched_uid,
                "zeek_http_count": len(matched_http),
                "zeek_dns_count": len(matched_dns),
                "zeek_ssl_count": len(matched_ssl),
            },
        )
        flow.flow_key = make_flow_key(src_ip, src_port, dst_ip, dst_port, transport)
        return flow

    def _match_zeek_connection(
        self,
        ndpi_row: Dict[str, Any],
        zeek_indexes: Dict[str, Any],
        transport: str,
    ) -> Dict[str, Any]:
        exact_key = build_exact_flow_tuple(
            ndpi_row.get("src_ip"),
            ndpi_row.get("src_port"),
            ndpi_row.get("dst_ip"),
            ndpi_row.get("dst_port"),
            transport,
        )
        canonical_key = build_canonical_flow_tuple(
            ndpi_row.get("src_ip"),
            ndpi_row.get("src_port"),
            ndpi_row.get("dst_ip"),
            ndpi_row.get("dst_port"),
            transport,
        )
        candidates = zeek_indexes["exact_conn_index"].get(exact_key, [])
        if not candidates:
            candidates = zeek_indexes["canonical_conn_index"].get(canonical_key, [])
        if not candidates:
            return {}
        if len(candidates) == 1:
            return candidates[0]

        ndpi_ts = safe_float(ndpi_row.get("first_seen")) or safe_float(ndpi_row.get("last_seen")) or 0.0
        return min(candidates, key=lambda record: abs((safe_float(record.get("ts")) or 0.0) - ndpi_ts))

    def _resolve_x509_records(
        self,
        ssl_records: Iterable[Dict[str, Any]],
        x509_by_fp: Dict[str, list[Dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        resolved: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ssl_record in ssl_records:
            for fingerprint in parse_zeek_vector(ssl_record.get("cert_chain_fps")):
                for record in x509_by_fp.get(fingerprint, []):
                    fp = normalize_text(record.get("fingerprint"))
                    if fp and fp not in seen:
                        seen.add(fp)
                        resolved.append(record)
        return resolved

    def _build_http_metadata(self, http_records: list[Dict[str, Any]]) -> HTTPMetadata:
        urls: list[str] = []
        content_types: list[str] = []
        for record in http_records:
            host = normalize_domain(record.get("host"))
            uri = normalize_text(record.get("uri")) or "/"
            if host:
                urls.append(f"http://{host}{uri}")
            mime_types = parse_zeek_vector(record.get("resp_mime_types"))
            content_types.extend(mime_types)

        first = http_records[0] if http_records else {}
        return HTTPMetadata(
            method=normalize_text(first.get("method")),
            host=normalize_domain(first.get("host")),
            uri=normalize_text(first.get("uri")),
            user_agent=normalize_text(first.get("user_agent")),
            status_code=safe_int(first.get("status_code")),
            urls=sorted(set(urls)),
            content_types=sorted(set(content_types)),
            raw_records=http_records,
        )

    def _build_dns_metadata(self, dns_records: list[Dict[str, Any]]) -> DNSMetadata:
        queries = sorted({normalize_domain(record.get("query")) for record in dns_records if normalize_domain(record.get("query"))})
        answers: set[str] = set()
        for record in dns_records:
            answers.update(parse_zeek_vector(record.get("answers")))
        first = dns_records[0] if dns_records else {}
        return DNSMetadata(
            query=normalize_domain(first.get("query")),
            qtype_name=normalize_text(first.get("qtype_name")),
            rcode_name=normalize_text(first.get("rcode_name")),
            answers=sorted(answers),
            queries=queries,
            raw_records=dns_records,
        )

    def _build_tls_metadata(
        self,
        ndpi_row: Dict[str, Any],
        ssl_records: list[Dict[str, Any]],
        x509_records: list[Dict[str, Any]],
        sni: str | None,
    ) -> TLSMetadata:
        first_ssl = ssl_records[0] if ssl_records else {}
        cert_subjects = [normalize_text(record.get("certificate.subject")) for record in x509_records]
        cert_issuers = [normalize_text(record.get("certificate.issuer")) for record in x509_records]
        san_dns: list[str] = []
        for record in x509_records:
            san_dns.extend(normalize_domain(item) for item in parse_zeek_vector(record.get("san.dns")))
        return TLSMetadata(
            version=normalize_text(ndpi_row.get("tls_version")) or normalize_text(first_ssl.get("version")),
            cipher=normalize_text(first_ssl.get("cipher")),
            curve=normalize_text(first_ssl.get("curve")),
            server_name=sni,
            next_protocol=normalize_text(first_ssl.get("next_protocol")),
            ja3s=normalize_text(ndpi_row.get("ja3s")),
            advertised_alpns=parse_zeek_vector(ndpi_row.get("advertised_alpns")),
            negotiated_alpn=normalize_text(ndpi_row.get("negotiated_alpn")),
            supported_versions=parse_zeek_vector(ndpi_row.get("tls_supported_versions")),
            cert_chain_fingerprints=[
                fingerprint
                for record in ssl_records
                for fingerprint in parse_zeek_vector(record.get("cert_chain_fps"))
            ],
            cert_subjects=[item for item in cert_subjects if item],
            cert_issuers=[item for item in cert_issuers if item],
            san_dns=[item for item in san_dns if item],
            sni_matches_cert=self._coerce_bool(first_ssl.get("sni_matches_cert")),
            established=self._coerce_bool(first_ssl.get("established")),
            raw_ssl_records=ssl_records,
            raw_x509_records=x509_records,
        )

    def _is_encrypted_flow(
        self,
        ndpi_row: Dict[str, Any],
        ssl_records: list[Dict[str, Any]],
        tls: TLSMetadata,
    ) -> bool:
        proto_text = " ".join(
            filter(
                None,
                [
                    normalize_text(ndpi_row.get("proto_stack")),
                    normalize_text(ndpi_row.get("ndpi_app")),
                    normalize_text(ndpi_row.get("ndpi_proto")),
                ],
            )
        ).lower()
        return any(hint in proto_text for hint in ENCRYPTED_PROTOCOL_HINTS) or bool(ssl_records) or bool(tls.version)

    def _infer_transport(self, ndpi_row: Dict[str, Any]) -> str:
        if normalize_text(ndpi_row.get("proto")):
            return normalize_text(ndpi_row.get("proto")).lower()
        protocol_number = safe_int(ndpi_row.get("protocol"))
        if protocol_number == 6:
            return "tcp"
        if protocol_number == 17:
            return "udp"
        return "unknown"

    def _classify_flow(self, flow: FlowMetadata) -> Tuple[bool, str | None, str]:
        sni_label = self._lookup_known_sni(flow.sni)
        if sni_label:
            return True, sni_label, "SNI 命中已知白名单"

        ndpi_app = (flow.ndpi_app or flow.proto_stack or "").lower()
        if ndpi_app in SYSTEM_PROTOCOL_LABELS:
            return True, SYSTEM_PROTOCOL_LABELS[ndpi_app], f"系统协议快速过滤: {ndpi_app}"

        if ndpi_app in NDPI_STRONG_HINT_LABELS:
            return True, NDPI_STRONG_HINT_LABELS[ndpi_app], f"nDPI 高置信应用识别: {ndpi_app}"

        if self._is_noise_or_local_discovery(flow):
            return True, "system:local_discovery", "广播/组播/链路本地流量，跳过 Agent"

        http_host = flow.http.host
        if http_host and self._lookup_known_sni(http_host):
            return True, self._lookup_known_sni(http_host), "HTTP Host 命中已知域名"

        if not flow.is_encrypted and (flow.http.host or ndpi_app in PLAINTEXT_PROTOCOL_HINTS):
            return False, None, "明文流量，交给 Agent 深挖内容"

        if flow.is_encrypted and not flow.sni:
            return False, None, "加密流量缺少可映射 SNI，需要 Agent 主动分析"

        if flow.is_encrypted:
            return False, None, "加密流量 SNI 未命中白名单，交给 Agent"

        return False, None, "未命中预处理规则，交给 Agent"

    def _build_preprocess_evidence(self, flow: FlowMetadata, is_known: bool) -> Dict[str, Any]:
        evidence = {
            "ndpi_app": flow.ndpi_app,
            "sni_source": "zeek_or_ndpi" if flow.sni else "none",
            "ip_scope": classify_ip_scope(flow.dst_ip),
            "is_encrypted": flow.is_encrypted,
            "http_host": flow.http.host,
            "dns_query": flow.dns.query,
        }
        if is_known and flow.preprocess_label:
            evidence["matched_label"] = flow.preprocess_label
        return evidence

    def _lookup_known_sni(self, sni: str | None) -> str | None:
        domain = normalize_domain(sni)
        if not domain:
            return None

        direct = self.known_sni.get(domain)
        if direct:
            return self._label_from_known_info(domain, direct)

        for key, info in self.known_sni.items():
            normalized_key = normalize_domain(key)
            if not normalized_key:
                continue
            if normalized_key.startswith("*.") and domain.endswith(normalized_key[1:]):
                return self._label_from_known_info(domain, info)
            if domain.endswith(f".{normalized_key}"):
                return self._label_from_known_info(domain, info)
        return None

    def _label_from_known_info(self, domain: str, info: Dict[str, Any]) -> str:
        app = normalize_text(info.get("app")) or extract_domain_brand(domain) or domain
        service_type = normalize_text(info.get("type")) or infer_service_type_from_port(None) or "web"
        return f"{app}:{service_type}"

    def _is_noise_or_local_discovery(self, flow: FlowMetadata) -> bool:
        dst_scope = classify_ip_scope(flow.dst_ip)
        src_scope = classify_ip_scope(flow.src_ip)
        ndpi_app = (flow.ndpi_app or "").lower()
        return (
            is_broadcast_or_multicast(flow.dst_ip)
            or dst_scope in {"link_local", "multicast"}
            or src_scope == "link_local"
            or (ndpi_app == "json" and is_broadcast_or_multicast(flow.dst_ip))
        )

    @staticmethod
    def _first_non_empty(values: Iterable[Any]) -> str | None:
        for value in values:
            normalized = normalize_text(value)
            if normalized:
                return normalized
        return None

    @staticmethod
    def _coerce_bool(value: Any) -> bool | None:
        if pd.isna(value):
            return None
        if isinstance(value, bool):
            return value
        text = normalize_text(value)
        if text is None:
            return None
        lowered = text.lower()
        if lowered in {"t", "true", "1", "yes"}:
            return True
        if lowered in {"f", "false", "0", "no"}:
            return False
        return None


preprocessor: TrafficPreprocessor | None = None


def init_preprocessor() -> TrafficPreprocessor:
    global preprocessor
    preprocessor = TrafficPreprocessor()
    return preprocessor
