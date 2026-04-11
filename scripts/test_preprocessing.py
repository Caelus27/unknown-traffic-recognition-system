# scripts/test_preprocessing.py
from pathlib import Path
import sys

# Ensure the project root is importable when running this script directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.preprocessing import init_preprocessor

preprocessor = init_preprocessor()

pcap_path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_pcaps/email1a.pcap"
result = preprocessor.process_pcap(pcap_path)

print("\n=== 处理完成 ===")
print(f"PCAP: {result['pcap_name']}")
print(f"总流数: {result['stats']['total_flows']}")
print(f"已知流量: {result['stats']['known_count']}")
print(f"未知流量: {result['stats']['unknown_count']}")
print(f"已知比例: {result['stats']['known_ratio']}%")

print("\n已知流量前3条示例:")
for item in result['known'][:3]:
    print(f"  {item.get('label', 'N/A')} | SNI: {item.get('sni')} | ndpi: {item.get('ndpi_app')}")

print("\n未知流量数量:", len(result['unknown']))
if result['unknown']:
    print("未知流量前1条示例:")
    print(result['unknown'][0])