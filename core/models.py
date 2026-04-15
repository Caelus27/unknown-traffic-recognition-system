from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any


try:
    from pydantic import BaseModel, ConfigDict, Field
except ModuleNotFoundError:  # pragma: no cover - exercised only in minimal envs
    BaseModel = None  # type: ignore[assignment]
    ConfigDict = None  # type: ignore[assignment]
    Field = None  # type: ignore[assignment]


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


if BaseModel is not None:

    class TrafficBaseModel(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)


    class HTTPMetadata(TrafficBaseModel):
        method: str | None = None
        host: str | None = None
        uri: str | None = None
        user_agent: str | None = None
        status_code: int | None = None
        urls: list[str] = Field(default_factory=list)
        content_types: list[str] = Field(default_factory=list)
        raw_records: list[dict[str, Any]] = Field(default_factory=list)


    class DNSMetadata(TrafficBaseModel):
        query: str | None = None
        qtype_name: str | None = None
        rcode_name: str | None = None
        answers: list[str] = Field(default_factory=list)
        queries: list[str] = Field(default_factory=list)
        raw_records: list[dict[str, Any]] = Field(default_factory=list)


    class TLSMetadata(TrafficBaseModel):
        version: str | None = None
        cipher: str | None = None
        curve: str | None = None
        server_name: str | None = None
        next_protocol: str | None = None
        ja3s: str | None = None
        advertised_alpns: list[str] = Field(default_factory=list)
        negotiated_alpn: str | None = None
        supported_versions: list[str] = Field(default_factory=list)
        cert_chain_fingerprints: list[str] = Field(default_factory=list)
        cert_subjects: list[str] = Field(default_factory=list)
        cert_issuers: list[str] = Field(default_factory=list)
        san_dns: list[str] = Field(default_factory=list)
        sni_matches_cert: bool | None = None
        established: bool | None = None
        raw_ssl_records: list[dict[str, Any]] = Field(default_factory=list)
        raw_x509_records: list[dict[str, Any]] = Field(default_factory=list)


    class FlowStats(TrafficBaseModel):
        start_ts: float | None = None
        end_ts: float | None = None
        duration: float | None = None
        total_bytes: int | None = None
        c_to_s_bytes: int | None = None
        s_to_c_bytes: int | None = None
        c_to_s_goodput_bytes: int | None = None
        s_to_c_goodput_bytes: int | None = None
        c_to_s_packets: int | None = None
        s_to_c_packets: int | None = None
        data_ratio: float | None = None
        flow_risk: str | None = None
        packet_length_bins: str | None = None


    class PcapExtractionStatus(TrafficBaseModel):
        status: str = "not_run"
        error: str | None = None
        packet_count: int = 0
        byte_count: int = 0


    class ClassificationModelResult(TrafficBaseModel):
        status: str = "not_run"
        model_name: str | None = None
        label: str | None = None
        probability: float | None = None
        topk: list[dict[str, Any]] = Field(default_factory=list)
        error: str | None = None


    class FlowMetadata(TrafficBaseModel):
        flow_id: int | str | None = None
        pcap_name: str | None = None
        src_ip: str
        src_port: int | None = None
        dst_ip: str
        dst_port: int | None = None
        transport: str = "unknown"
        proto_stack: str | None = None
        ndpi_app: str | None = None
        is_encrypted: bool = False
        sni: str | None = None
        http: HTTPMetadata = Field(default_factory=HTTPMetadata)
        dns: DNSMetadata = Field(default_factory=DNSMetadata)
        tls: TLSMetadata = Field(default_factory=TLSMetadata)
        stats: FlowStats = Field(default_factory=FlowStats)
        flow_key: str | None = None
        preprocess_reason: str = "unclassified"
        preprocess_label: str | None = None
        confidence: float | None = None
        unknown_pcap_path: str | None = None
        pcap_extraction: PcapExtractionStatus = Field(default_factory=PcapExtractionStatus)
        classification_model: ClassificationModelResult = Field(default_factory=ClassificationModelResult)
        raw_sources: dict[str, Any] = Field(default_factory=dict)

else:

    @dataclass
    class _DataclassDumpMixin:
        def model_dump(self, mode: str = "python", **_: Any) -> dict[str, Any]:
            return _jsonable(self)


    @dataclass
    class HTTPMetadata(_DataclassDumpMixin):
        method: str | None = None
        host: str | None = None
        uri: str | None = None
        user_agent: str | None = None
        status_code: int | None = None
        urls: list[str] = field(default_factory=list)
        content_types: list[str] = field(default_factory=list)
        raw_records: list[dict[str, Any]] = field(default_factory=list)


    @dataclass
    class DNSMetadata(_DataclassDumpMixin):
        query: str | None = None
        qtype_name: str | None = None
        rcode_name: str | None = None
        answers: list[str] = field(default_factory=list)
        queries: list[str] = field(default_factory=list)
        raw_records: list[dict[str, Any]] = field(default_factory=list)


    @dataclass
    class TLSMetadata(_DataclassDumpMixin):
        version: str | None = None
        cipher: str | None = None
        curve: str | None = None
        server_name: str | None = None
        next_protocol: str | None = None
        ja3s: str | None = None
        advertised_alpns: list[str] = field(default_factory=list)
        negotiated_alpn: str | None = None
        supported_versions: list[str] = field(default_factory=list)
        cert_chain_fingerprints: list[str] = field(default_factory=list)
        cert_subjects: list[str] = field(default_factory=list)
        cert_issuers: list[str] = field(default_factory=list)
        san_dns: list[str] = field(default_factory=list)
        sni_matches_cert: bool | None = None
        established: bool | None = None
        raw_ssl_records: list[dict[str, Any]] = field(default_factory=list)
        raw_x509_records: list[dict[str, Any]] = field(default_factory=list)


    @dataclass
    class FlowStats(_DataclassDumpMixin):
        start_ts: float | None = None
        end_ts: float | None = None
        duration: float | None = None
        total_bytes: int | None = None
        c_to_s_bytes: int | None = None
        s_to_c_bytes: int | None = None
        c_to_s_goodput_bytes: int | None = None
        s_to_c_goodput_bytes: int | None = None
        c_to_s_packets: int | None = None
        s_to_c_packets: int | None = None
        data_ratio: float | None = None
        flow_risk: str | None = None
        packet_length_bins: str | None = None


    @dataclass
    class PcapExtractionStatus(_DataclassDumpMixin):
        status: str = "not_run"
        error: str | None = None
        packet_count: int = 0
        byte_count: int = 0


    @dataclass
    class ClassificationModelResult(_DataclassDumpMixin):
        status: str = "not_run"
        model_name: str | None = None
        label: str | None = None
        probability: float | None = None
        topk: list[dict[str, Any]] = field(default_factory=list)
        error: str | None = None


    @dataclass
    class FlowMetadata(_DataclassDumpMixin):
        src_ip: str = "unknown"
        dst_ip: str = "unknown"
        flow_id: int | str | None = None
        pcap_name: str | None = None
        src_port: int | None = None
        dst_port: int | None = None
        transport: str = "unknown"
        proto_stack: str | None = None
        ndpi_app: str | None = None
        is_encrypted: bool = False
        sni: str | None = None
        http: HTTPMetadata = field(default_factory=HTTPMetadata)
        dns: DNSMetadata = field(default_factory=DNSMetadata)
        tls: TLSMetadata = field(default_factory=TLSMetadata)
        stats: FlowStats = field(default_factory=FlowStats)
        flow_key: str | None = None
        preprocess_reason: str = "unclassified"
        preprocess_label: str | None = None
        confidence: float | None = None
        unknown_pcap_path: str | None = None
        pcap_extraction: PcapExtractionStatus = field(default_factory=PcapExtractionStatus)
        classification_model: ClassificationModelResult = field(default_factory=ClassificationModelResult)
        raw_sources: dict[str, Any] = field(default_factory=dict)

