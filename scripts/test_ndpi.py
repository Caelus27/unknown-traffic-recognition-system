# scripts/test_ndpi.py
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.utils.ndpi_utils import init_ndpi_utils
from config import NDPI_READER

if len(sys.argv) < 2:
    print("用法: python scripts/test_ndpi.py <pcap_path>")
    sys.exit(1)

# 初始化 nDPI
ndpi_utils = init_ndpi_utils(NDPI_READER)

pcap_path = sys.argv[1]
print(f"正在测试 nDPI 处理: {pcap_path}")

summary = ndpi_utils.get_ndpi_summary(pcap_path)

print("\n=== nDPI 处理结果总结 ===")
for key, value in summary.items():
    print(f"{key}: {value}")

# 如果生成了 CSV，显示前几行关键列
output_file = Path(summary.get("output_file", ""))
if output_file.suffix == '.csv' and output_file.exists():
    with output_file.open("r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline()
    sep = "|" if "|" in first_line else ","

    df = pd.read_csv(output_file, sep=sep, nrows=5)
    df.columns = [c.lstrip("#").strip() for c in df.columns]

    print("\n=== CSV 前5行关键列预览 ===")
    print(df.columns.tolist())
    preview_cols = [
        "flow_id", "src_ip", "src_port", "dst_ip", "dst_port",
        "proto_stack", "ndpi_proto", "server_name_sni", "flow_risk"
    ]
    selected = [c for c in preview_cols if c in df.columns]
    print(df[selected].head() if selected else df.head())