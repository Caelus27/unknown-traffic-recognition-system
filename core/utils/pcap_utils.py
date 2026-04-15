from __future__ import annotations

import ipaddress
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from core.utils.helpers import dump_json_file, make_flow_key, normalize_text, safe_float, safe_int

logger = logging.getLogger(__name__)


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond"),
    b"\xa1\xb2\xc3\xd4": (">", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond"),
    b"\xa1\xb2\x3c\x4d": (">", "nanosecond"),
}

ETHERNET_LINKTYPE = 1
IPV4_ETHERTYPE = 0x0800
IPV6_ETHERTYPE = 0x86DD
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
TRANSPORT_BY_NUMBER = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
IPV6_EXTENSION_HEADERS = {0, 43, 44, 50, 51, 60}


@dataclass
class PacketInfo:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    transport: str
    timestamp: float


@dataclass
class FlowExtractionTarget:
    index: int
    flow_key: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    transport: str
    start_ts: float | None
    end_ts: float | None
    output_path: Path
    packets: list[tuple[bytes, bytes]] = field(default_factory=list)
    byte_count: int = 0

    def accepts(self, packet: PacketInfo) -> bool:
        packet_key = make_flow_key(
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.transport,
        )
        if packet_key != self.flow_key:
            return False
        if self.start_ts is not None and packet.timestamp < self.start_ts - 1.0:
            return False
        if self.end_ts is not None and packet.timestamp > self.end_ts + 1.0:
            return False
        return True


def create_unknown_flow_pcap_manifest(
    pcap_path: str | Path,
    unknown_flows: list[dict[str, Any]],
    task_id: str,
    task_dir: str | Path,
    timestamp: str,
) -> dict[str, Any]:
    """Extract per-flow classic PCAP files and write a manifest.

    The implementation is intentionally dependency-free so Phase 1 remains
    runnable even when tcpdump/scapy/pyshark are absent. Unsupported capture
    formats are recorded in the manifest instead of failing preprocessing.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    task_dir = Path(task_dir).expanduser().resolve()
    task_dir.mkdir(parents=True, exist_ok=True)

    targets = _build_targets(unknown_flows, task_dir)
    manifest = {
        "schema_version": "unknown_flows_pcap_manifest/v1",
        "task_id": task_id,
        "timestamp": timestamp,
        "pcap_name": pcap_path.name,
        "pcap_path": str(pcap_path),
        "unknown_flows_pcap_dir": str(task_dir),
        "flows": [],
    }

    if not targets:
        manifest["status"] = "ok"
        manifest["message"] = "no unknown flows"
        manifest["manifest_path"] = str(task_dir / "manifest.json")
        dump_json_file(task_dir / "manifest.json", manifest)
        return manifest

    try:
        global_header, byte_order, timestamp_unit, linktype = _read_pcap_global_header(pcap_path)
    except Exception as exc:
        logger.warning("无法解析 PCAP 头部，未知流切分跳过: %s", exc)
        return _write_failed_manifest(manifest, targets, task_dir, f"unsupported_pcap: {exc}")

    if linktype != ETHERNET_LINKTYPE:
        return _write_failed_manifest(manifest, targets, task_dir, f"unsupported_linktype: {linktype}")

    try:
        with pcap_path.open("rb") as handle:
            handle.seek(len(global_header))
            for packet_header, packet_data, timestamp_value in _iter_classic_pcap_packets(
                handle,
                byte_order,
                timestamp_unit,
            ):
                packet_info = _parse_ethernet_packet(packet_data, timestamp_value)
                if packet_info is None:
                    continue
                for target in targets:
                    if target.accepts(packet_info):
                        target.packets.append((packet_header, packet_data))
                        target.byte_count += len(packet_data)
    except Exception as exc:
        logger.warning("未知流 PCAP 切分失败: %s", exc)
        return _write_failed_manifest(manifest, targets, task_dir, f"extract_error: {exc}")

    for target in targets:
        _write_target_pcap(global_header, target)
        manifest["flows"].append(_target_manifest_entry(target))

    manifest["status"] = "ok"
    manifest["manifest_path"] = str(task_dir / "manifest.json")
    dump_json_file(task_dir / "manifest.json", manifest)
    return manifest


def _build_targets(unknown_flows: list[dict[str, Any]], task_dir: Path) -> list[FlowExtractionTarget]:
    targets: list[FlowExtractionTarget] = []
    for index, flow in enumerate(unknown_flows, start=1):
        src_ip = normalize_text(flow.get("src_ip")) or "unknown"
        dst_ip = normalize_text(flow.get("dst_ip")) or "unknown"
        src_port = safe_int(flow.get("src_port")) or 0
        dst_port = safe_int(flow.get("dst_port")) or 0
        transport = (normalize_text(flow.get("transport")) or "unknown").lower()
        flow_key = normalize_text(flow.get("flow_key")) or make_flow_key(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            transport,
        )
        stats = flow.get("stats") or {}
        output_path = task_dir / f"flow_{index:06d}.pcap"
        targets.append(
            FlowExtractionTarget(
                index=index,
                flow_key=flow_key,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                transport=transport,
                start_ts=safe_float(stats.get("start_ts")),
                end_ts=safe_float(stats.get("end_ts")),
                output_path=output_path,
            )
        )
    return targets


def _read_pcap_global_header(pcap_path: Path) -> tuple[bytes, str, str, int]:
    with pcap_path.open("rb") as handle:
        global_header = handle.read(24)
    if len(global_header) != 24:
        raise ValueError("file too small for classic pcap")
    magic = global_header[:4]
    if magic not in PCAP_MAGIC:
        raise ValueError("not a supported classic pcap file")
    byte_order, timestamp_unit = PCAP_MAGIC[magic]
    _, _, _, _, _, _, linktype = struct.unpack(f"{byte_order}IHHIIII", global_header)
    return global_header, byte_order, timestamp_unit, linktype


def _iter_classic_pcap_packets(
    handle: BinaryIO,
    byte_order: str,
    timestamp_unit: str,
):
    divisor = 1_000_000_000 if timestamp_unit == "nanosecond" else 1_000_000
    packet_header_struct = struct.Struct(f"{byte_order}IIII")
    while True:
        packet_header = handle.read(packet_header_struct.size)
        if not packet_header:
            break
        if len(packet_header) != packet_header_struct.size:
            break
        ts_sec, ts_fraction, incl_len, _ = packet_header_struct.unpack(packet_header)
        packet_data = handle.read(incl_len)
        if len(packet_data) != incl_len:
            break
        yield packet_header, packet_data, ts_sec + (ts_fraction / divisor)


def _parse_ethernet_packet(packet: bytes, timestamp_value: float) -> PacketInfo | None:
    if len(packet) < 14:
        return None
    offset = 14
    ethertype = struct.unpack("!H", packet[12:14])[0]
    while ethertype in VLAN_ETHERTYPES and len(packet) >= offset + 4:
        ethertype = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
        offset += 4

    if ethertype == IPV4_ETHERTYPE:
        return _parse_ipv4_packet(packet[offset:], timestamp_value)
    if ethertype == IPV6_ETHERTYPE:
        return _parse_ipv6_packet(packet[offset:], timestamp_value)
    return None


def _parse_ipv4_packet(payload: bytes, timestamp_value: float) -> PacketInfo | None:
    if len(payload) < 20:
        return None
    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(payload) < ihl:
        return None
    fragment_field = struct.unpack("!H", payload[6:8])[0]
    fragment_offset = fragment_field & 0x1FFF
    if fragment_offset:
        return None
    protocol_number = payload[9]
    src_ip = str(ipaddress.ip_address(payload[12:16]))
    dst_ip = str(ipaddress.ip_address(payload[16:20]))
    return _parse_transport(
        payload[ihl:],
        protocol_number,
        src_ip,
        dst_ip,
        timestamp_value,
    )


def _parse_ipv6_packet(payload: bytes, timestamp_value: float) -> PacketInfo | None:
    if len(payload) < 40 or payload[0] >> 4 != 6:
        return None
    next_header = payload[6]
    offset = 40
    src_ip = str(ipaddress.ip_address(payload[8:24]))
    dst_ip = str(ipaddress.ip_address(payload[24:40]))

    while next_header in IPV6_EXTENSION_HEADERS and len(payload) >= offset + 8:
        if next_header == 44:
            fragment_offset = struct.unpack("!H", payload[offset + 2 : offset + 4])[0] >> 3
            if fragment_offset:
                return None
            header_len = 8
        elif next_header == 51:
            header_len = (payload[offset + 1] + 2) * 4
        else:
            header_len = (payload[offset + 1] + 1) * 8
        next_header = payload[offset]
        offset += header_len
        if len(payload) < offset:
            return None

    return _parse_transport(
        payload[offset:],
        next_header,
        src_ip,
        dst_ip,
        timestamp_value,
    )


def _parse_transport(
    payload: bytes,
    protocol_number: int,
    src_ip: str,
    dst_ip: str,
    timestamp_value: float,
) -> PacketInfo | None:
    transport = TRANSPORT_BY_NUMBER.get(protocol_number, str(protocol_number))
    src_port = 0
    dst_port = 0
    if transport in {"tcp", "udp"}:
        if len(payload) < 4:
            return None
        src_port, dst_port = struct.unpack("!HH", payload[:4])
    return PacketInfo(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        transport=transport,
        timestamp=timestamp_value,
    )


def _write_target_pcap(global_header: bytes, target: FlowExtractionTarget) -> None:
    if not target.packets:
        return
    with target.output_path.open("wb") as handle:
        handle.write(global_header)
        for packet_header, packet_data in target.packets:
            handle.write(packet_header)
            handle.write(packet_data)


def _target_manifest_entry(target: FlowExtractionTarget, error: str | None = None) -> dict[str, Any]:
    status = "ok" if target.packets else "empty"
    return {
        "index": target.index,
        "flow_key": target.flow_key,
        "src_ip": target.src_ip,
        "src_port": target.src_port,
        "dst_ip": target.dst_ip,
        "dst_port": target.dst_port,
        "transport": target.transport,
        "unknown_pcap_path": str(target.output_path) if target.packets else None,
        "pcap_extraction": {
            "status": status if error is None else "error",
            "error": error,
            "packet_count": len(target.packets),
            "byte_count": target.byte_count,
        },
    }


def _write_failed_manifest(
    manifest: dict[str, Any],
    targets: list[FlowExtractionTarget],
    task_dir: Path,
    error: str,
) -> dict[str, Any]:
    manifest["status"] = "error"
    manifest["error"] = error
    manifest["manifest_path"] = str(task_dir / "manifest.json")
    manifest["flows"] = [_target_manifest_entry(target, error=error) for target in targets]
    dump_json_file(task_dir / "manifest.json", manifest)
    return manifest
