# core/utils/ndpi_utils.py
import subprocess
import pandas as pd
from pathlib import Path
from typing import Dict, Optional
import logging

from config import NDPI_PROCESSED_DIR

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NDPIUtils:
    """nDPI 工具封装类"""

    def __init__(self, ndpi_reader_path: str):
        self.ndpi_reader = Path(ndpi_reader_path).expanduser().resolve()
        if not self.ndpi_reader.exists():
            logger.warning(f"ndpiReader 可执行文件未找到: {self.ndpi_reader}")
            self.ndpi_reader = None

    def run_ndpi_on_pcap(self, pcap_path: str | Path, output_csv: Optional[Path] = None) -> Path:
        """运行 ndpiReader 处理 PCAP，返回输出 CSV 路径"""
        if not self.ndpi_reader:
            raise RuntimeError("ndpiReader 路径未正确配置，请在 config.py 中设置 NDPI_READER")

        pcap_path = Path(pcap_path).expanduser().resolve()
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP 文件不存在: {pcap_path}")

        if output_csv is None:
            output_csv = NDPI_PROCESSED_DIR / f"{pcap_path.stem}_ndpi_flows.csv"
        output_csv = output_csv.expanduser().resolve()

        output_csv.parent.mkdir(parents=True, exist_ok=True)

        # nDPI 5.x: -C 用于将流级结果直接写入 CSV 文件。
        cmd = [
            str(self.ndpi_reader),
            "-i", str(pcap_path),
            "-C", str(output_csv),
        ]

        logger.info(f"运行 nDPI（CSV模式）: {pcap_path.name}")
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            if not output_csv.exists() or output_csv.stat().st_size == 0:
                raise RuntimeError("nDPI 未生成有效 CSV 文件")

            size_kb = output_csv.stat().st_size / 1024
            logger.info(f"nDPI CSV 生成成功: {output_csv} ({size_kb:.1f} KB)")
            return output_csv

        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            logger.error(f"nDPI 执行失败: {stderr}")
            raise RuntimeError(f"nDPI 执行失败: {stderr}") from e
        except subprocess.TimeoutExpired:
            logger.error("nDPI 处理超时")
            raise

    def parse_ndpi_csv(self, csv_path: Path) -> pd.DataFrame:
        """解析 nDPI 生成的 CSV 文件"""
        if not csv_path.exists():
            logger.warning(f"nDPI CSV 文件不存在: {csv_path}")
            return pd.DataFrame()

        try:
            with csv_path.open("r", encoding="utf-8", errors="replace") as f:
                first_line = f.readline()

            sep = "|" if "|" in first_line else ","
            df = pd.read_csv(csv_path, sep=sep, on_bad_lines="skip", low_memory=False)
            df.columns = [c.lstrip("#").strip() for c in df.columns]

            # 对齐项目内期望字段命名。
            if "server_name_sni" in df.columns and "sni" not in df.columns:
                df["sni"] = df["server_name_sni"]

            if "ndpi_proto" in df.columns and "ndpi_app" not in df.columns:
                df["ndpi_app"] = df["ndpi_proto"]

            if "proto_stack" in df.columns:
                df["ndpi_proto"] = df["proto_stack"]

            if "flow_risk" in df.columns and "risk" not in df.columns:
                df["risk"] = df["flow_risk"]

            if "src_port" in df.columns:
                df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")

            if "dst_port" in df.columns:
                df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")

            if "duration" in df.columns:
                df["duration"] = pd.to_numeric(df["duration"], errors="coerce")
            
            logger.info(f"成功解析 nDPI CSV，共 {len(df)} 条流记录")
            return df
        except Exception as e:
            logger.error(f"解析 nDPI CSV 失败: {e}")
            return pd.DataFrame()

    def get_ndpi_summary(self, pcap_path: str | Path) -> Dict:
        """获取 nDPI 处理的概要统计"""
        csv_path = self.run_ndpi_on_pcap(pcap_path)
        df = self.parse_ndpi_csv(csv_path)

        if df.empty:
            return {"error": "nDPI 处理失败或无数据"}

        app_series = df.get("ndpi_app", pd.Series(dtype="object")).fillna("").astype(str).str.strip()
        proto_series = df.get("ndpi_proto", pd.Series(dtype="object")).fillna("").astype(str).str.strip()
        sni_series = df.get("sni", pd.Series(dtype="object")).fillna("").astype(str).str.strip()
        risk_series = df.get("risk", pd.Series(dtype="object")).fillna("").astype(str).str.strip()

        summary = {
            "total_flows": len(df),
            "unique_apps": app_series[app_series != ""].nunique(),
            "unique_protos": proto_series[proto_series != ""].nunique(),
            "sni_count": (sni_series != "").sum(),
            "top_apps": app_series[app_series != ""].value_counts().head(10).to_dict(),
            "risk_flows": (risk_series != "").sum(),
            "output_file": str(csv_path),
            "is_csv_mode": True,
        }

        logger.info(f"nDPI 总结: {summary['total_flows']} 条流 | "
                    f"识别到 {summary['unique_apps']} 个应用 | SNI数量: {summary['sni_count']}")
        return summary


# ==================== 全局实例（方便导入） ====================
# 注意：需要在 config.py 中配置 NDPI_READER 路径后才能正常使用
ndpi_utils = None

def init_ndpi_utils(ndpi_reader_path: str):
    global ndpi_utils
    ndpi_utils = NDPIUtils(ndpi_reader_path)
    return ndpi_utils
