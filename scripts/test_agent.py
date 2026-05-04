"""单独测试 Agent 模块（不跑预处理/分类模型）。

三种模式：

1) 健康检查（验证 mybot config + provider api_key + 网络）：
   python scripts/test_agent.py --ping

2) 用现成 chunk 跑一次 Agent，看输出 & schema 校验：
   python scripts/test_agent.py --chunk agent_workspace/inputs/email1a_xxx_chunk_01.json

3) 自定义 prompt，验证 AGENTS.md / SKILL.md 是否被加载：
   python scripts/test_agent.py --prompt "请用一句话告诉我你能用哪些工具，以及你的工作目标是什么。"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import AGENT_WORKSPACE_DIR, MYBOT_CONFIG_PATH  # noqa: E402
from core.agent.result_parser import parse_agent_outputs  # noqa: E402

logger = logging.getLogger("test_agent")


_CHUNK_PROMPT_TEMPLATE = """你是网络流量取证分析助手。

工作流：
1. 用 read_file 读取输入：{input_relpath}
2. 阅读 ./AGENTS.md 与 ./skills/traffic_classify/SKILL.md。
3. 对 flows[] 每条按 sni > active_fetch > cert_or_ip > behavior_stats > classification_model 优先级判断。
4. service_type 必须从 input.job.policy.service_type_vocab 中选取。
5. 把 AgentResult/v1 写到：{output_relpath}

完成后用一句话告诉我已写入哪个文件。
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agent 单独测试工具")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ping", action="store_true", help="发一句简单消息验证 provider")
    group.add_argument("--chunk", type=str, help="用已有的 inputs/*.json 跑一次 Agent")
    group.add_argument("--prompt", type=str, help="自定义 prompt 直接发给 Agent")
    parser.add_argument("--workspace", type=str, default=str(AGENT_WORKSPACE_DIR))
    parser.add_argument("--config", type=str, default=str(MYBOT_CONFIG_PATH))
    parser.add_argument("--session", type=str, default="test:agent")
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    config_path = Path(args.config).expanduser().resolve()

    if not config_path.is_file():
        print(f"❌ mybot 配置文件不存在: {config_path}")
        return 2

    try:
        from mybot import MyBot
    except ImportError:
        print("❌ 未安装 mybot；先执行 `pip install -e mybot-main`")
        return 2

    bot = MyBot.from_config(config_path=config_path, workspace=workspace)

    if args.ping:
        print("→ 发送 ping 消息...")
        result = await bot.run("请用一句话告诉我你现在的工作目录是什么。", session_key=args.session)
        print("← LLM 回复:")
        print(result.content or "(空回复)")
        return 0 if result.content else 1

    if args.prompt:
        print(f"→ 发送 prompt:\n{args.prompt}\n")
        result = await bot.run(args.prompt, session_key=args.session)
        print("← LLM 回复:")
        print(result.content or "(空回复)")
        return 0

    # --chunk 模式
    chunk_path = Path(args.chunk).expanduser().resolve()
    if not chunk_path.is_file():
        print(f"❌ chunk 文件不存在: {chunk_path}")
        return 2
    try:
        chunk_path.relative_to(workspace)
    except ValueError:
        print(f"❌ chunk 文件必须位于 workspace 内（restrictToWorkspace=true）: {workspace}")
        return 2

    output_path = workspace / "outputs" / f"{chunk_path.stem}_test_result.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()  # 清掉旧产物以便看新结果

    prompt = _CHUNK_PROMPT_TEMPLATE.format(
        input_relpath=str(chunk_path.relative_to(workspace)),
        output_relpath=str(output_path.relative_to(workspace)),
    )
    print(f"→ 输入: {chunk_path.relative_to(workspace)}")
    print(f"→ 期望输出: {output_path.relative_to(workspace)}")
    print(f"→ session: {args.session}\n")

    result = await bot.run(prompt, session_key=args.session)
    print("← LLM 文本回复:")
    print(result.content or "(空回复)")
    print()

    if not output_path.is_file():
        print("❌ LLM 没有写出 output 文件 —— 可能是 provider 反爬/限流，或 prompt 没让它真的调用 write_file。")
        return 1

    parsed = parse_agent_outputs([output_path], pcap_name=chunk_path.stem)
    print("✅ output 文件已生成，schema 校验后产物:")
    print(json.dumps(parsed, ensure_ascii=False, indent=2))
    if parsed.get("errors"):
        print("\n⚠️  schema 校验记录的 errors:")
        for err in parsed["errors"]:
            print(f"  - {err}")
        return 1
    print(f"\n✅ {len(parsed.get('decisions', []))} 条 decisions 全部通过 schema 校验")
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    args = parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
