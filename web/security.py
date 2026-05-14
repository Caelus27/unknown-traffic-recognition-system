"""PCAP 上传安全校验：扩展名 / 大小 / 魔数。"""

from __future__ import annotations

from pathlib import Path

MAX_PCAP_BYTES = 200 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class UploadValidationError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def validate_extension(filename: str | None) -> str:
    if not filename:
        raise UploadValidationError("missing filename")
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise UploadValidationError(
            f"unsupported extension: {suffix or '(none)'}; expected one of {sorted(ALLOWED_EXTENSIONS)}"
        )
    return suffix


def validate_magic(file_path: Path) -> None:
    with file_path.open("rb") as handle:
        header = handle.read(4)
    if header in _PCAP_MAGICS:
        return
    if header == _PCAPNG_MAGIC:
        return
    raise UploadValidationError("invalid pcap magic — file does not look like a pcap/pcapng capture")


def safe_display_name(filename: str | None, max_length: int = 120) -> str:
    """从用户提供的 filename 中抽取一个安全的展示名（不进入文件系统路径）。"""

    if not filename:
        return "upload.pcap"
    base = Path(filename).name  # 去掉所有目录成分
    base = base.replace("\x00", "")
    if len(base) > max_length:
        base = base[:max_length]
    return base or "upload.pcap"
