from pathlib import Path
import sys

# Ensure the project root is importable when running this script directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.utils.zeek_utils import run_zeek_on_pcap, extract_traffic_info, get_sni_list,get_flow_summary

if len(sys.argv) < 2:
    print("用法: python scripts/test_zeek.py <pcap_path>")
    print("示例: python scripts/test_zeek.py data/sample_pcaps/email1a.pcap")
    sys.exit(1)

pcap_path = sys.argv[1]
print(f"正在测试 PCAP: {pcap_path}")

# 1. 运行 Zeek
log_dir = run_zeek_on_pcap(pcap_path)

# 2. 提取信息
traffic_info = extract_traffic_info(log_dir)

# 3. 显示结果
print("\n=== Zeek 处理统计 ===")
print(f"总连接数: {traffic_info['stats']['total_flows']}")
print(f"TLS 流数量: {traffic_info['stats']['tls_flows']}")
print(f"包含 SNI 的流: {traffic_info['stats']['sni_count']}")
print(f"明文 HTTP 流: {traffic_info['stats']['http_flows']}")

print("\n=== 出现的 SNI（前15个） ===")
sni_list = get_sni_list(log_dir)
for sni in sni_list[:15]:
    print(sni)

# 显示流摘要示例
summary = get_flow_summary(log_dir)
if not summary.empty:
    print(f"\n流摘要示例 (前 8 条):")
    cols = ['sni', 'id.resp_h', 'duration', 'orig_bytes', 'resp_bytes']
    available_cols = [c for c in cols if c in summary.columns]
    print(summary[available_cols].head(8))