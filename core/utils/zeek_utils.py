# core/utils/zeek_utils.py
import subprocess
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional
import json
import logging
import gzip

from config import ZEEK_BIN, ZEEK_LOG_DIR

# logging.basicConfig(level=logging.INFO)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_zeek_on_pcap(pcap_path: str | Path, output_dir: Optional[Path] = None) -> Path:
    """运行 Zeek 处理单个 PCAP，返回日志所在目录"""
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP 文件不存在: {pcap_path}")

    if output_dir is None:
        output_dir = ZEEK_LOG_DIR / pcap_path.stem
    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        ZEEK_BIN, "-C", "-r", str(pcap_path),
        f"Log::default_logdir={output_dir}"
    ]

    logger.info(f"正在运行 Zeek 处理: {pcap_path.name}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=output_dir.parent)
        if result.stdout:
            logger.debug(f"Zeek 输出: {result.stdout.strip()}")
        logger.info(f"Zeek 处理完成，日志目录: {output_dir}")
        return output_dir
    except subprocess.CalledProcessError as e:
        logger.error(f"Zeek 执行失败: {e.stderr}")
        raise

def parse_zeek_log(log_path: Path) -> pd.DataFrame:
    """解析 Zeek 日志文件（支持 .log 或 .log.gz），跳过头部注释"""
    if not log_path.exists():
        logger.warning(f"日志文件不存在: {log_path}")
        return pd.DataFrame()

    open_func = gzip.open if log_path.suffix == '.gz' else open
    fields: List[str] = []

    # Zeek 日志列名在 #fields 行，先解析出来再加载数据。
    with open_func(log_path, 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('#fields\t'):
                fields = line.strip().split('\t')[1:]
                break

    if not fields:
        logger.warning(f"未找到 #fields 头部，无法解析: {log_path}")
        return pd.DataFrame()

    try:
        df = pd.read_csv(
            log_path,
            sep='\t',
            comment='#',
            names=fields,
            header=None,
            na_values=['-', '(empty)'],
            low_memory=False,
            on_bad_lines='skip'
        )
        #logger.debug(f"成功解析 {log_path.name}，共 {len(df)} 条记录")
        return df
    except Exception as e:
        logger.error(f"解析 {log_path.name} 失败: {e}")
        return pd.DataFrame()

def extract_traffic_info(zeek_log_dir: Path) -> Dict:
    """
    提取 Zeek 处理后的关键信息
    返回包含 conn、ssl、http 信息的字典
    """
    zeek_log_dir = Path(zeek_log_dir)
    
    # 基础流,ssl,http,dns,x509 信息
    conn_df = parse_zeek_log(zeek_log_dir / "conn.log")
    ssl_df = parse_zeek_log(zeek_log_dir / "ssl.log")
    http_df = parse_zeek_log(zeek_log_dir / "http.log")
    dns_df = parse_zeek_log(zeek_log_dir / "dns.log")
    x509_df = parse_zeek_log(zeek_log_dir / "x509.log")

    if not ssl_df.empty and 'server_name' in ssl_df.columns:
        ssl_df = ssl_df.rename(columns={'server_name': 'sni'})

    stats = {
        "total_flows": len(conn_df),
        "tls_flows": len(ssl_df),
        "http_flows": len(http_df),
        "dns_flows": len(dns_df),
        "x509_records": len(x509_df),
        "sni_count": int(ssl_df['sni'].notna().sum()) if not ssl_df.empty else 0
    }

    logger.info(f"Zeek 提取完成 → 总流: {stats['total_flows']} | "
                f"TLS流: {stats['tls_flows']} | SNI数量: {stats['sni_count']}")

    return {
        "conn": conn_df,
        "ssl": ssl_df,
        "http": http_df,
        "dns": dns_df,
        "x509": x509_df,
        "stats": stats,
        "log_dir": str(zeek_log_dir)
    }

def get_sni_list(zeek_log_dir: Path) -> List[str]:
    """快速获取所有出现的 SNI 列表（去重）"""
    ssl_df = parse_zeek_log(Path(zeek_log_dir) / "ssl.log")
    if ssl_df.empty:
        return []
    if 'server_name' in ssl_df.columns:
        ssl_df = ssl_df.rename(columns={'server_name': 'sni'})
    return ssl_df['sni'].dropna().unique().tolist()

def get_flow_summary(zeek_log_dir: Path) -> pd.DataFrame:
    """返回一个合并后的流摘要 DataFrame（方便后续过滤使用）"""
    zeek_log_dir = Path(zeek_log_dir)
    ssl_df = parse_zeek_log(zeek_log_dir / "ssl.log")
    conn_df = parse_zeek_log(zeek_log_dir / "conn.log")
    http_df = parse_zeek_log(zeek_log_dir / "http.log")
    dns_df = parse_zeek_log(zeek_log_dir / "dns.log")
    
    if ssl_df.empty:
        return pd.DataFrame()
    
    if 'server_name' in ssl_df.columns:
        ssl_df = ssl_df.rename(columns={'server_name': 'sni'})

    # 合并 conn 和 ssl（以 uid 关联）
    if 'uid' in conn_df.columns and 'uid' in ssl_df.columns:
        merged = ssl_df.merge(
            conn_df[['uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
                  'duration', 'orig_bytes', 'resp_bytes', 'proto']],
            on='uid', how='left'
        )
        if not http_df.empty and 'uid' in http_df.columns:
            merged = merged.merge(
                http_df[['uid', 'host', 'uri', 'method']].drop_duplicates('uid'),
                on='uid',
                how='left',
            )
        if not dns_df.empty and 'uid' in dns_df.columns:
            merged = merged.merge(
                dns_df[['uid', 'query', 'answers']].drop_duplicates('uid'),
                on='uid',
                how='left',
            )
        return merged
    return ssl_df


def load_known_sni_list(path: Path) -> Dict:
    """加载已知SNI白名单"""
    if not path.exists():
        logger.warning(f"known_sni_list.json 不存在，将使用空列表")
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_zeek_logs(zeek_log_dir: Path, pcap_name: str):
    """备份日志到 data/processed/zeek_logs/"""
    target_dir = ZEEK_LOG_DIR / pcap_name
    target_dir.mkdir(parents=True, exist_ok=True)
    # 这里可以添加复制日志文件的逻辑（暂时跳过，后面需要时再加）
    pass
