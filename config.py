import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent.absolute()

def _as_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_json_env(name: str, default):
    raw_value = os.getenv(name)
    if not raw_value:
        return default
    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return default


def _load_skill_dirs() -> tuple[Path, ...]:
    configured = os.getenv("AGENT_SKILL_DIRS", "")
    directories: list[Path] = []
    if configured:
        directories.extend(
            Path(item).expanduser().resolve()
            for item in configured.split(os.pathsep)
            if item.strip()
        )
    repo_skill_dir = (BASE_DIR / "skills").resolve()
    directories.append(repo_skill_dir)

    deduped: list[Path] = []
    seen: set[str] = set()
    for directory in directories:
        key = str(directory)
        if key not in seen:
            seen.add(key)
            deduped.append(directory)
    return tuple(deduped)


# 工具路径（请根据你的实际安装路径修改）
ZEEK_BIN = os.getenv("ZEEK_BIN", "/opt/zeek/bin/zeek")
NDPI_READER = os.getenv("NDPI_READER", "/home/caelus/nDPI-dev/example/ndpiReader")

# 数据路径
DATA_DIR = BASE_DIR / "data"
SAMPLE_PCAP_DIR = DATA_DIR / "sample_pcaps"
PROCESSED_DIR = DATA_DIR / "processed"
KNOWN_SNI_PATH = DATA_DIR / "known_sni_list.json"
KNOWN_RESULTS_DIR = PROCESSED_DIR / "known_results"
UNKNOWN_FLOWS_DIR = PROCESSED_DIR / "unknown_flows"
NDPI_PROCESSED_DIR = PROCESSED_DIR / "ndpi_processed"
ZEEK_LOG_DIR = PROCESSED_DIR / "zeek_logs"
PROCESSED_RESULTS_DIR = PROCESSED_DIR / "results"
FINAL_RESULTS_DIR = DATA_DIR / "results"
LOG_DIR = BASE_DIR / "logs"

# 创建目录
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
KNOWN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
UNKNOWN_FLOWS_DIR.mkdir(parents=True, exist_ok=True)
NDPI_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
ZEEK_LOG_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
FINAL_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
