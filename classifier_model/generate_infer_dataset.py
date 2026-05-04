#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""
Standalone preprocessing script:
Convert raw pcap/pcapng files into ET-BERT inference TSV files.
"""

import argparse
import csv
import re
import shutil
import subprocess
import sys
from pathlib import Path

FLOW_PCAP_PATTERN = re.compile(r"flow_(\d{6,})\.pcap$", re.IGNORECASE)


def parse_flow_index(pcap_path):
    """Extract integer flow index from filenames like 'flow_000007.pcap'."""
    if not pcap_path:
        return ""
    match = FLOW_PCAP_PATTERN.search(str(pcap_path))
    if not match:
        return ""
    return str(int(match.group(1)))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from packet_features import (
    extract_transport_payload,
    packet_to_bigram_text,
    window_payloads_to_bigram_text,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert raw pcap/pcapng files into inference TSV files for run_classifier_infer.py."
    )
    parser.add_argument("--input_path", required=True, help="Directory containing raw pcap/pcapng files.")
    parser.add_argument("--output_dir", required=True, help="Directory used to store generated TSV files.")
    parser.add_argument(
        "--dataset_level",
        choices=["packet", "flow"],
        default="packet",
        help="Split large pcaps by packet or by flow before extracting features.",
    )
    parser.add_argument("--payload_length", type=int, default=64, help="Payload token length.")
    parser.add_argument("--payload_packet", type=int, default=5, help="Packet count for flow-level features.")
    parser.add_argument("--splitcap_path", default=None, help="Path to SplitCap.exe. Required only for flow mode.")
    parser.add_argument("--editcap_path", default=None, help="Path to editcap.exe. Required for pcapng files.")
    parser.add_argument("--limit", type=int, default=None, help="Optional max number of inference samples.")
    parser.add_argument(
        "--max_packets_per_capture",
        type=int,
        default=None,
        help="Optional cap for packet mode to stop reading huge captures early.",
    )
    parser.add_argument(
        "--max_records_per_capture",
        type=int,
        default=None,
        help="Optional cap on exported records per raw capture.",
    )
    parser.add_argument(
        "--packet_stride",
        type=int,
        default=1,
        help="In packet mode, export one valid packet every N raw packets.",
    )
    parser.add_argument(
        "--feature_mode",
        choices=["fixed_offset", "payload_only", "window_payload"],
        default="fixed_offset",
        help="Packet feature extraction mode.",
    )
    parser.add_argument("--window_payload_packets", type=int, default=5, help="Packet window size in window_payload mode.")
    parser.add_argument("--window_payload_stride", type=int, default=5, help="Packet window stride in window_payload mode.")
    parser.add_argument(
        "--window_payload_tokens_per_packet",
        type=int,
        default=None,
        help="Optional token budget per packet in window_payload mode.",
    )
    parser.add_argument("--keep_intermediate", action="store_true", help="Keep converted/split intermediate files.")
    return parser.parse_args()


def collect_capture_files(input_dir):
    capture_files = []
    for path in sorted(Path(input_dir).rglob("*")):
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}:
            capture_files.append(path)
    return capture_files


def ensure_tool_exists(tool_path, tool_name):
    if not tool_path or not Path(tool_path).is_file():
        raise FileNotFoundError(f"{tool_name} not found: {tool_path}")


def convert_to_pcap(source_path, converted_dir, editcap_path):
    if source_path.suffix.lower() == ".pcap":
        return source_path

    converted_dir.mkdir(parents=True, exist_ok=True)
    target_path = converted_dir / f"{source_path.stem}.pcap"
    ensure_tool_exists(editcap_path, "editcap")
    subprocess.run([editcap_path, "-F", "pcap", str(source_path), str(target_path)], check=True)
    return target_path


def split_capture_file(pcap_path, split_root, splitcap_path, dataset_level):
    ensure_tool_exists(splitcap_path, "SplitCap")
    output_dir = split_root / pcap_path.stem
    output_dir.mkdir(parents=True, exist_ok=True)

    if dataset_level == "flow":
        command = [splitcap_path, "-r", str(pcap_path), "-s", "session", "-o", str(output_dir)]
    else:
        command = [splitcap_path, "-r", str(pcap_path), "-s", "packets", "1", "-o", str(output_dir)]

    subprocess.run(command, check=True)
    return output_dir


def size_kb(file_path):
    return float(f"{file_path.stat().st_size / 1000:.3f}")


def _load_scapy():
    try:
        import scapy.all as scapy_module
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError("scapy is required for packet-mode preprocessing.") from exc
    return scapy_module


def extract_packet_records_from_capture(
    capture_path,
    payload_length,
    max_packets=None,
    packet_stride=1,
    feature_mode="fixed_offset",
):
    if packet_stride < 1:
        raise ValueError("--packet_stride must be >= 1")

    scapy = _load_scapy()
    records = []
    packet_reader = scapy.PcapReader(str(capture_path))

    try:
        for packet_index, packet in enumerate(packet_reader, start=1):
            if (packet_index - 1) % packet_stride != 0:
                continue

            text = packet_to_bigram_text(bytes(packet), payload_length, feature_mode=feature_mode)
            if not text:
                continue

            records.append(
                {
                    "text_a": text,
                    "source_pcap": str(capture_path),
                    "split_sample": f"{capture_path}#packet_{packet_index}",
                }
            )
            if max_packets is not None and len(records) >= max_packets:
                break
    finally:
        packet_reader.close()

    return records


def extract_window_payload_records_from_capture(
    capture_path,
    payload_length,
    window_packets=5,
    window_stride=5,
    tokens_per_packet=None,
    max_windows=None,
):
    if window_packets < 1:
        raise ValueError("--window_payload_packets must be >= 1")
    if window_stride < 1:
        raise ValueError("--window_payload_stride must be >= 1")

    scapy = _load_scapy()

    payload_records = []
    records = []
    skip_payloads = 0
    packet_reader = scapy.PcapReader(str(capture_path))

    try:
        for packet_index, packet in enumerate(packet_reader, start=1):
            payload = extract_transport_payload(bytes(packet))
            if not payload:
                continue
            if skip_payloads > 0:
                skip_payloads -= 1
                continue

            payload_records.append((packet_index, payload))

            while len(payload_records) >= window_packets:
                window = payload_records[:window_packets]
                text = window_payloads_to_bigram_text(
                    [payload for _, payload in window],
                    payload_length=payload_length,
                    tokens_per_packet=tokens_per_packet,
                )
                if text:
                    first_packet = window[0][0]
                    last_packet = window[-1][0]
                    records.append(
                        {
                            "text_a": text,
                            "source_pcap": str(capture_path),
                            "split_sample": f"{capture_path}#payload_window_{first_packet}-{last_packet}",
                        }
                    )
                    if max_windows is not None and len(records) >= max_windows:
                        return records

                if window_stride >= window_packets:
                    skip_payloads = window_stride - window_packets
                    payload_records = []
                else:
                    payload_records = payload_records[window_stride:]
    finally:
        packet_reader.close()

    return records


def is_valid_flow_sample(sample_path):
    return sample_path.stat().st_size > 0 and size_kb(sample_path) >= 5


def extract_feature(sample_path, dataset_level, payload_length, payload_packet):
    from flow_features import get_feature_flow, get_feature_packet

    try:
        if dataset_level == "flow":
            feature_data = get_feature_flow(
                str(sample_path),
                payload_len=payload_length,
                payload_pac=payload_packet,
            )
        else:
            feature_data = get_feature_packet(
                str(sample_path),
                payload_len=payload_length,
            )
    except Exception as exc:
        print(f"Skip sample for extraction error: {sample_path} ({exc})")
        return None

    if feature_data == -1 or not feature_data:
        return None
    feature_text = feature_data[0].strip()
    return feature_text or None


def write_infer_tsv(records, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    label_file = output_dir / "infer_dataset.tsv"
    nolabel_file = output_dir / "nolabel_infer_dataset.tsv"
    manifest_file = output_dir / "infer_manifest.tsv"

    with label_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["label", "text_a"])
        for record in records:
            writer.writerow([0, record["text_a"]])

    with nolabel_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["text_a"])
        for record in records:
            writer.writerow([record["text_a"]])

    with manifest_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["row_id", "source_pcap", "split_sample", "flow_index"])
        for index, record in enumerate(records, start=1):
            writer.writerow(
                [
                    index,
                    record["source_pcap"],
                    record["split_sample"],
                    parse_flow_index(record["source_pcap"]),
                ]
            )

    return label_file, nolabel_file, manifest_file


def build_records(args):
    input_dir = Path(args.input_path)
    output_dir = Path(args.output_dir)
    converted_dir = output_dir / "converted_pcaps"
    split_root = output_dir / "splitcap"

    capture_files = collect_capture_files(input_dir)
    if not capture_files:
        raise FileNotFoundError(f"No pcap/pcapng files found under: {input_dir}")

    print(f"Found {len(capture_files)} raw capture files.")
    records = []

    for capture_index, capture_file in enumerate(capture_files, start=1):
        print(f"[{capture_index}/{len(capture_files)}] Processing {capture_file}")
        converted_pcap = convert_to_pcap(capture_file, converted_dir, args.editcap_path)

        if args.dataset_level == "packet":
            remaining_samples = None
            if args.limit is not None:
                remaining_samples = args.limit - len(records)
                if remaining_samples <= 0:
                    return records

            packet_limit = args.max_records_per_capture if args.max_records_per_capture is not None else args.max_packets_per_capture
            if remaining_samples is not None:
                packet_limit = remaining_samples if packet_limit is None else min(packet_limit, remaining_samples)

            if args.feature_mode == "window_payload":
                capture_records = extract_window_payload_records_from_capture(
                    converted_pcap,
                    payload_length=args.payload_length,
                    window_packets=args.window_payload_packets,
                    window_stride=args.window_payload_stride,
                    tokens_per_packet=args.window_payload_tokens_per_packet,
                    max_windows=packet_limit,
                )
            else:
                capture_records = extract_packet_records_from_capture(
                    converted_pcap,
                    payload_length=args.payload_length,
                    max_packets=packet_limit,
                    packet_stride=args.packet_stride,
                    feature_mode=args.feature_mode,
                )

            for record in capture_records:
                record["source_pcap"] = str(capture_file)
            records.extend(capture_records)

            if args.limit is not None and len(records) >= args.limit:
                return records[: args.limit]
        else:
            split_dir = split_capture_file(converted_pcap, split_root, args.splitcap_path, args.dataset_level)
            split_samples = sorted(path for path in split_dir.rglob("*") if path.is_file() and path.suffix.lower() == ".pcap")

            for sample_path in split_samples:
                if not is_valid_flow_sample(sample_path):
                    continue

                feature_text = extract_feature(sample_path, args.dataset_level, args.payload_length, args.payload_packet)
                if not feature_text:
                    continue

                records.append(
                    {
                        "text_a": feature_text,
                        "source_pcap": str(capture_file),
                        "split_sample": str(sample_path),
                    }
                )

                if args.limit is not None and len(records) >= args.limit:
                    return records

    return records


def cleanup_intermediate(output_dir):
    for name in ["converted_pcaps", "splitcap"]:
        target = output_dir / name
        if target.exists():
            shutil.rmtree(target)


def main():
    args = parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = build_records(args)
    if not records:
        raise RuntimeError("No valid inference samples were generated. Please check input files and split settings.")

    label_file, nolabel_file, manifest_file = write_infer_tsv(records, output_dir)
    print(f"Generated {len(records)} inference samples.")
    print(f"Labeled TSV: {label_file}")
    print(f"Nolabel TSV: {nolabel_file}")
    print(f"Manifest TSV: {manifest_file}")

    if not args.keep_intermediate:
        cleanup_intermediate(output_dir)
        print("Intermediate converted/split files have been removed.")


if __name__ == "__main__":
    main()
