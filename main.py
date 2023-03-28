import os
import traceback
import discord
import asyncio

from discord.ext import commands

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

prefix = "?"
description = """?"""
cogs_dir = "commands"

bot = commands.Bot(command_prefix=prefix, description=description, intents=intents)
tree = bot.tree


@bot.event
async def on_ready():
    print("Ready!")


@bot.command()
async def sync(ctx):
    try:
        await tree.sync(guild=discord.Object(id=997708022778450020))
        await ctx.reply("Synced!")
    except Exception as e:
        await ctx.reply(e)


async def main():
    async with bot:
        for extension in [f.replace('.py', '') for f in os.listdir(cogs_dir) if os.path.isfile(os.path.join(cogs_dir, f))]:
            try:
                await bot.load_extension(cogs_dir + "." + extension)
            except (discord.ClientException, ModuleNotFoundError):
                print(f'Failed to load extension {extension}.')
                traceback.print_exc()

        await bot.start("MTA4NDk1Mjk1NzQ1MzM1NzEwOA.GHF8Tc.v53WCopE5PICKbYlWNY-uBMxUwr89Qco6NSgpc")

if __name__ == '__main__':
    asyncio.run(main())
