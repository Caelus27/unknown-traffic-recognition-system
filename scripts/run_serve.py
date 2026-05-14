"""启动 Web 服务（FastAPI + uvicorn）。"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _autodetect_mybot_config() -> None:
    """如果用户没显式设 MYBOT_CONFIG_PATH，按 mybot CLI 的习惯做向上查找。

    顺序：CWD → 项目根 → $HOME，每层尝试 `.mybot/config.json`。
    第一个含可用 apiKey 的 config 即采用。
    本仓库默认的 `agent_workspace/config.json` 无 apiKey，自动跳过它。
    """

    if os.getenv("MYBOT_CONFIG_PATH"):
        return

    candidates: list[Path] = []
    seen: set[Path] = set()
    for start in (Path.cwd(), PROJECT_ROOT, Path.home()):
        cur = start.resolve()
        while True:
            cand = cur / ".mybot" / "config.json"
            if cand not in seen:
                seen.add(cand)
                candidates.append(cand)
            if cur.parent == cur:
                break
            cur = cur.parent

    for cand in candidates:
        if not cand.is_file():
            continue
        try:
            payload = json.loads(cand.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if _has_api_key(payload):
            os.environ["MYBOT_CONFIG_PATH"] = str(cand)
            print(f"[run_serve] using mybot config: {cand}", file=sys.stderr)
            return


def _has_api_key(payload: dict) -> bool:
    providers = (payload or {}).get("providers") or {}
    if not isinstance(providers, dict):
        return False
    for cfg in providers.values():
        if isinstance(cfg, dict):
            key = cfg.get("apiKey") or cfg.get("api_key")
            if key and str(key).strip():
                return True
    return False


_autodetect_mybot_config()


def _autoenable_classifier() -> None:
    """检测到 ET-BERT 权重就自动启用分类模型，让 chunk 输入里 hints.classification_model 不再为 null。"""

    if os.getenv("CLASSIFIER_ENABLE"):
        return
    model_bin = PROJECT_ROOT / "classifier_model" / "assets" / "models" / "best_model.bin"
    vocab = PROJECT_ROOT / "classifier_model" / "assets" / "models" / "encryptd_vocab.txt"
    env_bin = os.getenv("CLASSIFIER_MODEL_BIN")
    env_vocab = os.getenv("CLASSIFIER_VOCAB")
    if env_bin:
        model_bin = Path(env_bin).expanduser()
    if env_vocab:
        vocab = Path(env_vocab).expanduser()

    if model_bin.is_file() and vocab.is_file():
        os.environ["CLASSIFIER_ENABLE"] = "true"
        os.environ.setdefault(
            "CLASSIFIER_ADAPTER",
            "core.classifier.etbert_adapter:run_etbert_classifier",
        )
        os.environ.setdefault("CLASSIFIER_MODEL_NAME", "etbert_v1")
        print(f"[run_serve] auto-enabled ET-BERT classifier ({model_bin})", file=sys.stderr)
    else:
        print(
            f"[run_serve] classifier weights not found ({model_bin}); "
            "agent will see classification_model.label = null",
            file=sys.stderr,
        )


_autoenable_classifier()

import uvicorn  # noqa: E402

from web.app import app  # noqa: E402


def main() -> int:
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
