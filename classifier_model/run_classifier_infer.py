"""
Standalone inference script for ET-BERT classification.
"""

import argparse
import json
import sys
from collections import Counter
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
    return parser.parse_args()


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

    for src_batch, seg_batch in batch_loader(args.batch_size, src, seg):
        src_batch = src_batch.to(device)
        seg_batch = seg_batch.to(device)
        with torch.no_grad():
            _, logits = model(src_batch, None, seg_batch)

        predicted_labels.extend(torch.argmax(logits, dim=1).cpu().numpy().tolist())

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


if __name__ == "__main__":
    main()

