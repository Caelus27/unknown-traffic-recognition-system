"""
Standalone inference script for ET-BERT classification.
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import torch

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from uer.model_loader import load_model
from uer.opts import infer_opts
from uer.utils import str2tokenizer
from uer.utils.config import load_hyperparam
from uer.utils.constants import CLS_TOKEN, SEP_TOKEN

from modeling_classifier import Classifier


LABEL_NAMES = {
    0: "bulk-transfer",
    1: "interactive",
    2: "stream",
    3: "vpn",
    4: "web",
}

FLOW_PCAP_PATTERN = re.compile(r"flow_(\d{6,})\.pcap$", re.IGNORECASE)


def batch_loader(batch_size, src, seg):
    instances_num = src.size(0)
    for i in range(instances_num // batch_size):
        src_batch = src[i * batch_size : (i + 1) * batch_size, :]
        seg_batch = seg[i * batch_size : (i + 1) * batch_size, :]
        yield src_batch, seg_batch

    if instances_num > (instances_num // batch_size) * batch_size:
        src_batch = src[(instances_num // batch_size) * batch_size :, :]
        seg_batch = seg[(instances_num // batch_size) * batch_size :, :]
        yield src_batch, seg_batch


def read_dataset(args, path):
    dataset = []
    columns = {}

    with open(path, mode="r", encoding="utf-8") as f:
        for line_id, line in enumerate(f):
            if line_id == 0:
                for i, column_name in enumerate(line.strip().split("\t")):
                    columns[column_name] = i
                continue

            line = line.strip().split("\t")
            if "text_b" not in columns:
                text_a = line[columns["text_a"]]
                src = args.tokenizer.convert_tokens_to_ids([CLS_TOKEN] + args.tokenizer.tokenize(text_a))
                seg = [1] * len(src)
            else:
                text_a = line[columns["text_a"]]
                text_b = line[columns["text_b"]]
                src_a = args.tokenizer.convert_tokens_to_ids([CLS_TOKEN] + args.tokenizer.tokenize(text_a) + [SEP_TOKEN])
                src_b = args.tokenizer.convert_tokens_to_ids(args.tokenizer.tokenize(text_b) + [SEP_TOKEN])
                src = src_a + src_b
                seg = [1] * len(src_a) + [2] * len(src_b)

            if len(src) > args.seq_length:
                src = src[: args.seq_length]
                seg = seg[: args.seq_length]

            while len(src) < args.seq_length:
                src.append(0)
                seg.append(0)

            dataset.append((src, seg))

    return dataset


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    infer_opts(parser)
    parser.add_argument("--pooling", choices=["mean", "max", "first", "last"], default="first", help="Pooling type.")
    parser.add_argument("--labels_num", type=int, required=True, help="Number of prediction labels.")
    parser.add_argument(
        "--tokenizer",
        choices=["bert", "char", "space"],
        default="bert",
        help="Tokenizer type.",
    )
    parser.add_argument(
        "--per_pcap_output",
        default=None,
        help=(
            "Optional JSON path. When set, group predictions by source_pcap "
            "(read from infer_manifest.tsv beside the test TSV) and emit one entry "
            "per PCAP with majority-voted label, mean probability, and topk."
        ),
    )
    parser.add_argument(
        "--manifest_path",
        default=None,
        help=(
            "Override path to infer_manifest.tsv. Defaults to "
            "'<test_path_dir>/infer_manifest.tsv'."
        ),
    )
    return parser.parse_args()


def _parse_flow_index(pcap_path):
    if not pcap_path:
        return None
    match = FLOW_PCAP_PATTERN.search(str(pcap_path))
    if not match:
        return None
    return int(match.group(1))


def _read_manifest(manifest_path):
    rows = []
    with open(manifest_path, mode="r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            rows.append(row)
    return rows


def _aggregate_per_pcap(manifest_rows, probs):
    """Group rows by source_pcap and aggregate label distribution."""
    grouped = defaultdict(list)
    for row, prob_vector in zip(manifest_rows, probs):
        source_pcap = row.get("source_pcap") or ""
        grouped[source_pcap].append(prob_vector)

    results = []
    for source_pcap, prob_vectors in grouped.items():
        stacked = torch.stack(prob_vectors, dim=0)
        mean_prob = stacked.mean(dim=0)
        sorted_probs, sorted_indices = torch.sort(mean_prob, descending=True)
        top_label_id = int(sorted_indices[0].item())
        top_prob = float(sorted_probs[0].item())
        topk = [
            {
                "label": LABEL_NAMES.get(int(idx.item()), str(int(idx.item()))),
                "label_id": int(idx.item()),
                "probability": float(p.item()),
            }
            for idx, p in zip(sorted_indices[: min(3, sorted_indices.size(0))], sorted_probs[: min(3, sorted_probs.size(0))])
        ]
        results.append(
            {
                "pcap_path": source_pcap,
                "flow_index": _parse_flow_index(source_pcap),
                "label_id": top_label_id,
                "label": LABEL_NAMES.get(top_label_id, str(top_label_id)),
                "probability": top_prob,
                "topk": topk,
                "sample_count": len(prob_vectors),
            }
        )
    results.sort(key=lambda item: (item.get("flow_index") is None, item.get("flow_index") or 0))
    return results


def main():
    args = parse_args()
    args = load_hyperparam(args)

    args.tokenizer = str2tokenizer[args.tokenizer](args)

    model = Classifier(args)
    model = load_model(model, args.load_model_path)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)
    if torch.cuda.device_count() > 1:
        print(f"{torch.cuda.device_count()} GPUs are available. Using DataParallel.")
        model = torch.nn.DataParallel(model)

    dataset = read_dataset(args, args.test_path)
    src = torch.LongTensor([sample[0] for sample in dataset])
    seg = torch.LongTensor([sample[1] for sample in dataset])

    instances_num = src.size(0)
    print("The number of prediction instances:", instances_num)

    prediction_path = Path(args.prediction_path)
    prediction_path.parent.mkdir(parents=True, exist_ok=True)

    model.eval()
    predicted_labels = []
    prob_vectors = []

    for src_batch, seg_batch in batch_loader(args.batch_size, src, seg):
        src_batch = src_batch.to(device)
        seg_batch = seg_batch.to(device)
        with torch.no_grad():
            _, logits = model(src_batch, None, seg_batch)

        probs_batch = torch.softmax(logits, dim=1).cpu()
        for row_index in range(probs_batch.size(0)):
            prob_vectors.append(probs_batch[row_index])
        predicted_labels.extend(torch.argmax(probs_batch, dim=1).numpy().tolist())

    total = len(predicted_labels)
    if total == 0:
        raise RuntimeError("No samples were predicted; check the input TSV.")

    counts = Counter(predicted_labels)
    results = [
        {
            "label": LABEL_NAMES.get(int(label_id), str(int(label_id))),
            "prob": count / total,
        }
        for label_id, count in counts.most_common(2)
    ]

    with open(prediction_path, mode="w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"Predicted {total} samples; saved top-2 aggregate to {prediction_path}")
    print(json.dumps(results, ensure_ascii=False, indent=2))

    if args.per_pcap_output:
        manifest_path = (
            Path(args.manifest_path)
            if args.manifest_path
            else Path(args.test_path).parent / "infer_manifest.tsv"
        )
        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"--per_pcap_output requires manifest file at: {manifest_path}"
            )
        manifest_rows = _read_manifest(manifest_path)
        if len(manifest_rows) != total:
            raise RuntimeError(
                f"Manifest row count ({len(manifest_rows)}) does not match prediction "
                f"count ({total}); manifest={manifest_path}"
            )

        per_pcap_results = _aggregate_per_pcap(manifest_rows, prob_vectors)
        per_pcap_path = Path(args.per_pcap_output)
        per_pcap_path.parent.mkdir(parents=True, exist_ok=True)
        with per_pcap_path.open("w", encoding="utf-8") as handle:
            json.dump(per_pcap_results, handle, ensure_ascii=False, indent=2)
        print(f"Saved per-pcap predictions ({len(per_pcap_results)} entries) to {per_pcap_path}")


if __name__ == "__main__":
    main()

