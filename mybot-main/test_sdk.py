import asyncio
from mybot import MyBot

async def main():
    bot = MyBot.from_config(
        config_path="C:/Users/86178/.mybot/config.json",
        workspace="C:/Users/86178/Desktop/workspace"
    )
    result = await bot.run(
        "nihao",
        session_key="proj:alice"  # 同一会话用同一个 key
    )
    print(result.content)

asyncio.run(main())
