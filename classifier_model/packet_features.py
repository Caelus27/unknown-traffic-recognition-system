#!/usr/bin/python3
# -*- coding:utf-8 -*-

import binascii


IPV6_EXTENSION_HEADERS = {0, 43, 44, 50, 51, 60}


def bigram_tokenize_hex(payload_hex, payload_length):
    tokens = []
    for index in range(0, max(len(payload_hex) - 2, 0), 2):
        if len(tokens) >= payload_length:
            break
        tokens.append(payload_hex[index : index + 4])
    return " ".join(tokens).strip()


def packet_to_bigram_text(packet_bytes, payload_length, feature_mode="fixed_offset"):
    if feature_mode == "fixed_offset":
        packet_hex = binascii.hexlify(packet_bytes).decode()
        payload_hex = packet_hex[76:] if len(packet_hex) > 76 else packet_hex
    elif feature_mode == "payload_only":
        payload = extract_transport_payload(packet_bytes)
        if not payload:
            return ""
        payload_hex = binascii.hexlify(payload).decode()
    else:
        raise ValueError("feature_mode must be either 'fixed_offset' or 'payload_only'")

    return bigram_tokenize_hex(payload_hex, payload_length)


def window_payloads_to_bigram_text(payloads, payload_length, tokens_per_packet=None):
    if not payloads:
        return ""

    if tokens_per_packet is None:
        tokens_per_packet = max(1, payload_length // len(payloads))
    if tokens_per_packet < 1:
        raise ValueError("tokens_per_packet must be >= 1")

    tokens = []
    for payload in payloads:
        payload_hex = binascii.hexlify(payload).decode()
        packet_text = bigram_tokenize_hex(payload_hex, tokens_per_packet)
        if packet_text:
            tokens.extend(packet_text.split())
        if len(tokens) >= payload_length:
            break

    return " ".join(tokens[:payload_length]).strip()


def extract_transport_payload(packet_bytes):
    packet = bytes(packet_bytes)
    network_offset = _find_network_offset(packet)
    if network_offset is None or network_offset >= len(packet):
        return b""

    version = packet[network_offset] >> 4
    if version == 4:
        return _extract_ipv4_transport_payload(packet, network_offset)
    if version == 6:
        return _extract_ipv6_transport_payload(packet, network_offset)
    return b""


def _find_network_offset(packet):
    if not packet:
        return None

    first_nibble = packet[0] >> 4
    if first_nibble in (4, 6):
        return 0

    if len(packet) < 14:
        return None

    offset = 14
    ether_type = int.from_bytes(packet[12:14], "big")
    while ether_type in (0x8100, 0x88A8) and len(packet) >= offset + 4:
        ether_type = int.from_bytes(packet[offset + 2 : offset + 4], "big")
        offset += 4

    if ether_type in (0x0800, 0x86DD):
        return offset
    return None


def _extract_ipv4_transport_payload(packet, ip_offset):
    if len(packet) < ip_offset + 20:
        return b""

    ihl = (packet[ip_offset] & 0x0F) * 4
    if ihl < 20 or len(packet) < ip_offset + ihl:
        return b""

    total_length = int.from_bytes(packet[ip_offset + 2 : ip_offset + 4], "big")
    if total_length == 0:
        ip_end = len(packet)
    else:
        ip_end = min(len(packet), ip_offset + total_length)

    fragment = int.from_bytes(packet[ip_offset + 6 : ip_offset + 8], "big")
    fragment_offset = fragment & 0x1FFF
    if fragment_offset != 0:
        return b""

    protocol = packet[ip_offset + 9]
    transport_offset = ip_offset + ihl
    return _extract_tcp_udp_payload(packet, transport_offset, ip_end, protocol)


def _extract_ipv6_transport_payload(packet, ip_offset):
    if len(packet) < ip_offset + 40:
        return b""

    payload_length = int.from_bytes(packet[ip_offset + 4 : ip_offset + 6], "big")
    ip_end = min(len(packet), ip_offset + 40 + payload_length) if payload_length else len(packet)
    next_header = packet[ip_offset + 6]
    transport_offset = ip_offset + 40

    while next_header in IPV6_EXTENSION_HEADERS:
        if next_header == 44:
            if len(packet) < transport_offset + 8:
                return b""
            fragment_info = int.from_bytes(packet[transport_offset + 2 : transport_offset + 4], "big")
            if fragment_info & 0xFFF8:
                return b""
            next_header = packet[transport_offset]
            transport_offset += 8
            continue

        if next_header == 51:
            if len(packet) < transport_offset + 2:
                return b""
            header_length = (packet[transport_offset + 1] + 2) * 4
        elif next_header == 50:
            return b""
        else:
            if len(packet) < transport_offset + 2:
                return b""
            header_length = (packet[transport_offset + 1] + 1) * 8

        next_header = packet[transport_offset]
        transport_offset += header_length
        if transport_offset > ip_end:
            return b""

    return _extract_tcp_udp_payload(packet, transport_offset, ip_end, next_header)


def _extract_tcp_udp_payload(packet, transport_offset, packet_end, protocol):
    if protocol == 6:
        if len(packet) < transport_offset + 20:
            return b""
        tcp_header_length = (packet[transport_offset + 12] >> 4) * 4
        if tcp_header_length < 20:
            return b""
        payload_offset = transport_offset + tcp_header_length
        if payload_offset > packet_end:
            return b""
        return packet[payload_offset:packet_end]

    if protocol == 17:
        if len(packet) < transport_offset + 8:
            return b""
        udp_length = int.from_bytes(packet[transport_offset + 4 : transport_offset + 6], "big")
        udp_end = min(packet_end, transport_offset + udp_length) if udp_length else packet_end
        payload_offset = transport_offset + 8
        if payload_offset > udp_end:
            return b""
        return packet[payload_offset:udp_end]

    return b""
