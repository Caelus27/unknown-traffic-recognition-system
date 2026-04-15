from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.preprocess_compat import normalize_legacy_preprocess_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert a legacy preprocessing JSON into PreprocessResult/v1.")
    parser.add_argument("input", help="Legacy preprocessing JSON path")
    parser.add_argument("-o", "--output", help="Optional output path; input is never modified")
    args = parser.parse_args()

    result = normalize_legacy_preprocess_file(args.input, args.output)
    print(f"schema_version: {result['schema_version']}")
    print(f"known: {len(result.get('known', []))}")
    print(f"unknown: {len(result.get('unknown', []))}")
    if args.output:
        print(f"wrote: {args.output}")


if __name__ == "__main__":
    main()
