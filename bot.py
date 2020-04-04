import discord
from discord.ext import tasks, commands
from lib.htb import HTBot
import config as cfg
from trio import run as trio_run
import asyncio
from concurrent.futures import ThreadPoolExecutor
import functools
import pdb

description = """HideAndSec's slave bot"""
bot = commands.Bot(command_prefix='>', description=description)

htbot = HTBot(cfg.HTB['email'], cfg.HTB['password'], cfg.HTB['api_token'])

THREADS = {
    "refresh_users": ThreadPoolExecutor(max_workers=1),
    "refresh_boxs": ThreadPoolExecutor(max_workers=1),
    "refresh_challs": ThreadPoolExecutor(max_workers=1),
    "writeup_links": ThreadPoolExecutor(max_workers=3),
    "writeup_dl": ThreadPoolExecutor(max_workers=1),
    "get_box": ThreadPoolExecutor(max_workers=4),
    "get_user": ThreadPoolExecutor(max_workers=4),
    "shoutbox": ThreadPoolExecutor(max_workers=1),
    "ippsec": ThreadPoolExecutor(max_workers=2)
}

LOOP = asyncio.get_event_loop()

#Start

@bot.event
async def on_ready():
    print('Logged in as')
    print(bot.user.name)
    print(bot.user.id)
    print('------')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.listening, name=">help"))
    try:
        bot.add_cog(tasksCog(bot))
    except:
        pass

    if cfg.options["writeup_legit"]:
        print("Le bot est lancé en mode writeup legit !")

#Tasks

class tasksCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.htb_login.start()
        self.check_host_vip.start()
        self.check_notif.start()
        self.refresh_boxs.start()
        self.refresh_all_challs.start()
        self.refresh_all_users.start()
        self.refresh_ippsec.start()
        self.manage_channels.start()
        self.refresh_shoutbox.start()

    @tasks.loop(seconds=3.0) #Toutes les 3 secondes, check les notifications
    async def check_notif(self):
        notif = htbot.notif
        if notif["update_role"]["state"]:
            content = notif["update_role"]["content"]
            await update_role(content["discord_id"], content["prev_rank"], content["new_rank"])
            htbot.notif["update_role"]["state"] = False

        elif notif["new_user"]["state"]:
            content = notif["new_user"]["content"]
            shoutbox = await get_shoutbox_channel()
            guilds = bot.guilds
            for guild in guilds:
                if guild.name == cfg.discord['guild_name']:
                    member = guild.get_member(content["discord_id"])
            await shoutbox.send("👋 Bienvenue {} ! Heureux de t'avoir parmis nous.\nTu es arrivé avec le rang {} !".format(member.mention, content["level"]))
            embed = await thread_get_user(content["htb_id"])
            msg = await shoutbox.send(embed=embed)
            await msg.add_reaction("👋")
            htbot.notif["new_role"]["state"] = False

        elif notif["box_pwn"]["state"]:
            content = notif["box_pwn"]["content"]
            shoutbox = await get_shoutbox_channel()
            guilds = bot.guilds
            for guild in guilds:
                if guild.name == cfg.discord['guild_name']:
                    member = guild.get_member(content["discord_id"])
            msg = await shoutbox.send("👏 {} a eu le {} de {} !".format(member.mention, content["pwn"], content["box_name"]))
            await msg.add_reaction("👏")
            htbot.notif["box_pwn"]["state"] = False

        elif notif["chall_pwn"]["state"]:
            content = notif["chall_pwn"]["content"]
            shoutbox = await get_shoutbox_channel()
            guilds = bot.guilds
            for guild in guilds:
                if guild.name == cfg.discord['guild_name']:
                    member = guild.get_member(content["discord_id"])
            msg = await shoutbox.send("👏 {} a réussi le challenge {} de la catégorie {} !".format(member.mention, content["chall_name"], content["chall_type"]))
            await msg.add_reaction("👏")
            htbot.notif["chall_pwn"]["state"] = False

        elif notif["new_box"]["state"]:
            content = notif["new_box"]["content"]
            shoutbox = await get_shoutbox_channel()
            if content["incoming"] == True:
                await shoutbox.send("⏱️ La box {} arrive dans {} ! ⏱️".format(content["box_name"], content["time"]))
            else:
                msg = await shoutbox.send("@here 🚨 La nouvelle box {} est en ligne ! 🚨\nAurez-vous le first blood ? 🩸".format(content["box_name"]))
                await msg.add_reaction("🩸")
                box = await thread_get_box(content["box_name"])
                await shoutbox.send("", embed=box["embed"])
            htbot.notif["new_box"]["state"] = False

        elif notif["vip_upgrade"]["state"]:
            content = notif["vip_upgrade"]["content"]
            shoutbox = await get_shoutbox_channel()
            guilds = bot.guilds
            for guild in guilds:
                if guild.name == cfg.discord['guild_name']:
                    member = guild.get_member(content["discord_id"])
            msg = await shoutbox.send("🍾 {} est devenu VIP ! Préparez le champagne et le caviar 🥂".format(member.mention))
            await msg.add_reaction("🍾")
            await msg.add_reaction("🥂")
            htbot.notif["vip_upgrade"]["state"] = False


    @tasks.loop(seconds=3.0) #Toutes les 3 secondes
    async def refresh_shoutbox(self):
        LOOP.run_in_executor(THREADS["shoutbox"], trio_run, htbot.shoutbox)

    @tasks.loop(seconds=1800.0) #Toutes les 30 minutes
    async def htb_login(self):
        trio_run(htbot.login)

    @tasks.loop(seconds=1800.0) #Toutes les 10 minutes
    async def check_host_vip(self):
        trio_run(htbot.check_if_host_is_vip)

    @tasks.loop(seconds=60.0) #Toutes les minutes
    async def refresh_boxs(self):
        LOOP.run_in_executor(THREADS["refresh_boxs"], trio_run, htbot.refresh_boxs)

    @tasks.loop(seconds=180.0) #Toutes les 3 minutes
    async def refresh_all_challs(self):
        LOOP.run_in_executor(THREADS["refresh_challs"], trio_run, htbot.refresh_all_challs)

    @tasks.loop(seconds=600.0) #Toutes les 10 minutes
    async def refresh_all_users(self):
        LOOP.run_in_executor(THREADS["refresh_users"], trio_run, htbot.refresh_all_users)

    @tasks.loop(seconds=600.0) #Toutes les 10 minutes
    async def refresh_ippsec(self):
        LOOP.run_in_executor(THREADS["ippsec"], trio_run, htbot.refresh_ippsec)

    @tasks.loop(seconds=60.0) #Toutes les minutes
    async def manage_channels(self):
        guilds = bot.guilds
        for guild in guilds:
            if guild.name == cfg.discord['guild_name']:
                categories = guild.categories
                for category in categories:
                    if "box-retired" in category.name.lower():
                        box_retired_cat = category
                    elif "box-active" in category.name.lower():
                        box_active_cat = category
                channels = box_active_cat.text_channels
                for channel in channels:
                    box_status = htbot.check_box(channel.name)
                    if box_status == "retired":
                        await channel.edit(category=box_retired_cat)
                        await channel.send("🔒 **{}** a été retirée, le channel a donc été déplacé vers la catégorie **{}**. 🔒".format(channel.name.capitalize(), box_retired_cat.name))


#Commands

@bot.command()
async def hello(ctx):
    """Says Hello World"""
    await ctx.send("Hello World")

@bot.command()
async def echo(ctx, *, content='🤔'):
    """A simple echo command"""
    await ctx.send(content)

@bot.command()
async def ping(ctx):
    """Want to ping pong ?"""
    await ctx.send(":ping_pong: Pong ! {}".format(bot.latency))

async def send_verif_instructions(user):
    embed = discord.Embed(color=0x9acc14)
    embed.add_field(name="Step 1: Log in to your HackTheBox Account", value="Log in to your HackTheBox account and go to the settings page.")
    embed.set_image(url="https://image.noelshack.com/fichiers/2019/48/3/1574858388-unknown.png")
    await user.send(embed=embed)
    embed = discord.Embed(color=0x9acc14)
    embed.add_field(name="Step 2: Locate the Identification key", value="In the settings tab, you should be able to identify a field called \"Account Identifier\", click on the green button to copy the string.")
    embed.set_image(url="https://image.noelshack.com/fichiers/2019/48/3/1574858586-capture.png")
    await user.send(embed=embed)
    embed = discord.Embed(color=0x9acc14)
    embed.add_field(name="Step 3: Verify", value="Proceed to send the bot your account identification string by:\n>verify <string>\n\nYour rank will be synchronized with HTB shortly.")
    embed.set_image(url="https://image.noelshack.com/fichiers/2019/48/3/1574859271-egqgqegqeg.png")
    await user.send(embed=embed)

@bot.command()
async def verify(ctx, content=""):
    """Verify your HTB account"""
    if str(ctx.channel.type) == "private":
        if content:
            verify_rep = trio_run(htbot.verify_user, ctx.author.id, content)
            if verify_rep == "already_in":
                await ctx.send("You already have verified your HTB account.")
            elif verify_rep == "wrong_id":
                await ctx.send("This Account Identifier does not work.\nAre you sure you followed the instructions correctly ?")
            else:
                guilds = bot.guilds
                for guild in guilds:
                    if guild.name == cfg.discord['guild_name']:
                        roles = guild.roles
                        role_name = cfg.roles[verify_rep.lower()]
                        for role in roles:
                            if role.name == role_name:
                                member = guild.get_member(ctx.author.id)
                                await member.add_roles(role)
                embed = discord.Embed(title="Roles added", description=cfg.roles[verify_rep.lower()], color=0x14ff08)
                await ctx.send(embed=embed)
        else:
            await ctx.send("Je crois que tu as oublié ton Account Identifier.")
            await send_verif_instructions(ctx.author)
    else:
        if content:
            await ctx.message.delete()
            await ctx.send("😱 N'envoie pas ça ici {} !\nViens donc en privé, je t'ai envoyé les instructions.".format(ctx.author.mention))
            await send_verif_instructions(ctx.author)
        else:
            await ctx.send("{} Viens en privé, je t'ai envoyé les instructions.".format(ctx.author.mention))
            await send_verif_instructions(ctx.author)

@bot.command()
async def get_box(ctx, *, content=""):
    """Get info on a box"""
    # Args parser
    args = content.split()
    count = 0
    matrix = False
    query = []
    target_flag = False

    while count < len(args):
        if (args[count] == "-m" or args[count] == "--matrix") and not matrix:
            matrix = True
            if target_flag:
                break
            else:
                count += 1
                continue

        else:
            if not target_flag:
                target_flag = True
            query.append(args[count])
            count += 1

    target = " ".join(query)

    if target:
        if matrix:
            box = await thread_get_box(target, matrix=True)
        else:
            box = await thread_get_box(target)

        if box:
                await ctx.send("", embed=box["embed"])
        else:
            await ctx.send("Cette box n'existe pas.")

    else:
        if str(ctx.channel.type) == "private":
            await ctx.send("Tu n'as pas précisé la box.")
        else:
            box_name = ctx.channel.name.lower()
            box_status = htbot.check_box(box_name)
            if box_status:
                if matrix:
                    box = await thread_get_box(box_name, matrix=True)
                else:
                    box = await thread_get_box(box_name)

                await ctx.send("", embed=box["embed"])

            else:
                await ctx.send("Tu n'as pas précisé la box.")


async def thread_get_box(name="name", matrix=False, last=False):
    return await LOOP.run_in_executor(THREADS["get_box"], trio_run, functools.partial(htbot.get_box, name, matrix, last))


@bot.command()
async def last_box(ctx, param=""):
    """Get info on the newest box"""
    if param:
        if param.lower() == "-m" or param.lower() == "--matrix":
            box = await thread_get_box(matrix=True, last=True)
        else:
            await ctx.send("Paramètres incorrectes.")
            return False
    else:
        box = await thread_get_box(last=True)

    await ctx.send("", embed=box["embed"])

@bot.command()
async def get_user(ctx, name=""):
    """Stalk your competitors"""
    if name:
        htb_id = trio_run(htbot.htb_id_by_name, name)
        if htb_id:
            embed = await thread_get_user(str(htb_id))
            await ctx.send(embed=embed)
        else:
            await ctx.send("Utilisateur non trouvé.")
    else:
        await ctx.send("T'as pas oublié un truc ? :tired_face:")

async def thread_get_user(htb_id):
    return await LOOP.run_in_executor(THREADS["get_user"], trio_run, functools.partial(htbot.get_user, htb_id))

@bot.command()
async def me(ctx):
    """Get your HTB info"""
    htb_id = htbot.discord_htb_converter(ctx.author.id, discord_to_htb=True)
    if htb_id:
        embed = await thread_get_user(str(htb_id))
        await ctx.send(embed=embed)
    else:
        await ctx.send("Vous n'avez pas enregistré de compte HTB.")

@bot.command()
async def leaderboard(ctx):
    """Get the leaderboard of the guild"""
    board = htbot.leaderboard()
    if board:
        guilds = bot.guilds
        for guild in guilds:
            if guild.name == cfg.discord['guild_name']:
                bot_guild = guild
            else:
                await ctx.send("Erreur.")
                return False

        text = ""
        count = 0
        for user in board:
            count += 1
            if count == 1:
                text += "👑 **{}. {}** (Points : {}, Ownership : {})\n".format(count, bot_guild.get_member(user["discord_id"]).display_name, user["points"], user["ownership"])
            elif count == 2:
                text += "💠 **{}. {}** (Points : {}, Ownership : {})\n".format(count, bot_guild.get_member(user["discord_id"]).display_name, user["points"], user["ownership"])
            elif count == 3:
                text += "🔶 **{}. {}** (Points : {}, Ownership : {})\n".format(count, bot_guild.get_member(user["discord_id"]).display_name, user["points"], user["ownership"])
            else:
                text += "➡ **{}. {}** (Points : {}, Ownership : {})\n".format(count, bot_guild.get_member(user["discord_id"]).display_name, user["points"], user["ownership"])

        embed = discord.Embed(title="🏆 Leaderboard 🏆 | {}".format(cfg.discord["guild_name"]), color=0x9acc14, description=text)
        await ctx.send(embed=embed)
    else:
        await ctx.send("Aucun compte HTB enregistré.\nFaites >verify pour le faire !")

async def update_role(discord_id, prev_rank, new_rank):
    guilds = bot.guilds
    for guild in guilds:
        if guild.name == cfg.discord['guild_name']:
            member = guild.get_member(discord_id)
            roles = guild.roles
            role_to_delete_name = cfg.roles[prev_rank.lower()]
            role_to_add_name = cfg.roles[new_rank.lower()]
            for role in roles:
                if role.name == role_to_add_name:
                    role_to_add = role
            roles = member.roles
            count = 0
            for role in roles:
                if role.name == role_to_delete_name:
                    roles[count] = role_to_add
                count += 1
            await member.edit(roles=roles)

    shoutbox = await get_shoutbox_channel()
    msg = await shoutbox.send("🎉 Félicitations {}, tu es passé au rang {} ! 🎉".format(member.mention, new_rank))
    await msg.add_reaction("🎉")


async def get_shoutbox_channel():
    guilds = bot.guilds
    for guild in guilds:
        if guild.name == cfg.discord['guild_name']:
            channels = guild.channels
            for channel in channels:
                if channel.name == "shoutbox":
                    return channel

@bot.command()
async def list_boxes(ctx, *, content=""):
    """list all active boxs, by difficulty or not"""

    # Args parser
    args = content.split()
    count = 0
    remaining = False
    query = []
    target_flag = False

    while count < len(args):
        if (args[count] == "-r" or args[count] == "--remaining") and not remaining:
            remaining = True
            if target_flag:
                break
            else:
                count += 1
                continue

        else:
            if not target_flag:
                target_flag = True
            query.append(args[count])
            count += 1

    type = " ".join(query).lower()

    if type:
        if type in ["easy", "medium", "hard", "insane"]:
            if remaining:
                board = htbot.list_boxes(type=type, remaining=True, discord_id=ctx.author.id)
            else:
                board = htbot.list_boxes(type=type)

            if board["status"] == "ok":
                await ctx.send("", embed=board["embed"])
                return True
            elif board["status"] == "not_sync":
                await ctx.send("Vous n'avez pas synchronisé votre compte HTB.\nVoir : **>man verify**")
                return False
            else:
                await ctx.send("Erreur.")
                return False

        else:
            await ctx.send("Difficulté inconnue.")
    else:
        if remaining:
            board = htbot.list_boxes(remaining=True, discord_id=ctx.author.id)
        else:
            board = htbot.list_boxes()

        if board["status"] == "ok":
            await ctx.send("", embed=board["embed"])
            return True
        elif board["status"] == "not_sync":
            await ctx.send("Vous n'avez pas synchronisé votre compte HTB.\nVoir : **>man verify**")
            return False
        else:
            await ctx.send("Erreur.")
            return False

@bot.command()
async def list_challs(ctx, *, content=""):
    """list all active challs, by difficulty or not"""

    # Args parser
    args = content.split()
    count = 0
    remaining = False
    difficulty = False
    category = False
    categories = ["reversing", "crypto", "stego", "pwn", "web", "misc", "forensics", "mobile", "osint"]
    difficulties = ["easy", "medium", "hard"]

    while count < len(args):
        if (args[count] == "-r" or args[count] == "--remaining") and not remaining:
            remaining = True
            count += 1
            continue

        elif (args[count] == "-d" or args[count] == "--difficulty") and not difficulty:
            if args[count + 1] and args[count + 1].lower() in difficulties:
                difficulty = args[count + 1].lower()
                count += 2
                continue
            else:
                if args[count + 1]:
                    await ctx.send("Je ne connais pas la difficulté \"{}\".\nLes difficultés existantes pour les challenges sont : **Easy, Medium et Hard.**".format(args[count + 1]))
                else:
                    await ctx.send("Vous n'avez pas précisé la difficulté.\nLes difficultés existantes pour les challenges sont : **Easy, Medium et Hard.**")
                return False

        elif args[count].lower() in categories:
            category = args[count].lower()
            count += 1
            continue

        else:
            await ctx.send("Je ne connais pas le paramètre \"{}\".\nVoir : **>man list_challs**".format(args[count]))
            return False

    board = htbot.list_challs(category=category, type=difficulty, remaining=remaining, discord_id=ctx.author.id)
    if board["status"] == "ok":
        await ctx.send("", embed=board["embed"])
        return True
    elif board["status"] == "not_sync":
        await ctx.send("Vous n'avez pas synchronisé votre compte HTB.\nVoir : **>man verify**")
        return False
    else:
        await ctx.send("Erreur.")
        return False


@bot.command()
async def work_on(ctx, *, content=""):
    """Do this command when you start a new box"""

    # Args parser
    args = content.split()
    count = 0
    box = False
    chall = False
    query = []
    target_flag = False

    while count < len(args):
        if (args[count] == "-b" or args[count] == "--box") and not box:
            box = True
            if target_flag:
                break
            else:
                count += 1
                continue

        elif (args[count] == "-c" or args[count] == "--chall") and not chall:
            chall = True
            if target_flag:
                break
            else:
                count += 1
                continue

        else:
            if not target_flag:
                target_flag = True
            query.append(args[count])
            count += 1

    if (box and chall) or (not box and not chall):
        await ctx.send("Erreur.")
        return False

    target = " ".join(query)

    if target:
        if box:
            #Si le nom de la box est précisé
            box_name = target.lower()
            box_status = htbot.check_box(box_name)
            if box_status:
                status = trio_run(functools.partial(htbot.work_on, target, ctx.author.id, box=True))
                if not status:
                    print("Erreur.")
                    return False

                guilds = bot.guilds
                for guild in guilds:
                    if guild.name == cfg.discord['guild_name']:
                        channels = guild.channels
                        for channel in channels:
                            if channel.name == box_name:
                                if status == "success":
                                    await ctx.send("Le channel {} est à ta disposition, bonne chance ! ❤".format(channel.mention))
                                    return True
                                elif status == "already_owned":
                                    await ctx.send("Tu as déjà terminé cette box, mais le channel {} reste à ta disposition ❤".format(channel.mention))
                                    return True

                        #Si le channel n'existe pas encore
                        categories = guild.categories
                        if box_status == "active":
                            for category in categories:
                                if "box-active" in category.name.lower():
                                    await guild.create_text_channel(name=box_name, category=category)
                                    channels = guild.channels
                                    for channel in channels:
                                        if channel.name == box_name:
                                            if status == "success":
                                                await ctx.send("J'ai créé le channel {}, il est à ta disposition ! Bonne chance ❤".format(channel.mention))
                                            elif status == "already_owned":
                                                await ctx.send("Tu as déjà terminé cette box, mais j'ai quand même créé le channel {} ! Il est à ta disposition, bonne chance ❤".format(channel.mention))

                                            box = await thread_get_box(box_name, matrix=True)
                                            await channel.send("✨ Channel créé ! {}".format(ctx.author.mention))
                                            await channel.send("", embed=box["embed"])
                                            return True
                        elif box_status == "retired":
                            for category in categories:
                                if "box-retired" in category.name.lower():
                                    await guild.create_text_channel(name=box_name, category=category)
                                    channels = guild.channels
                                    for channel in channels:
                                        if channel.name == box_name:
                                            if status == "success":
                                                await ctx.send("J'ai créé le channel {}, il est à ta disposition ! Bonne chance ❤".format(channel.mention))
                                            elif status == "already_owned":
                                                await ctx.send("Tu as déjà terminé cette box, mais j'ai quand même créé le channel {} ! Il est à ta disposition, bonne chance ❤".format(channel.mention))

                                            box = await thread_get_box(box_name, matrix=True)
                                            await channel.send("✨ Channel créé ! {}".format(ctx.author.mention))
                                            await channel.send("", embed=box["embed"])
                                            return True

            else:
                await ctx.send("Cette box n'existe pas.")

        elif chall:
            chall_status = htbot.check_chall(target)
            if chall_status:
                status = trio_run(functools.partial(htbot.work_on, target, ctx.author.id, chall=True))
                if not status:
                    print("Erreur.")
                    return False
                elif status == "success":
                    await ctx.send("Bonne chance {} ! ❤".format(ctx.author.mention))
                    return True
                elif status == "already_owned":
                    await ctx.send("Tu as déjà terminé ce challenge !")
                    return True
            else:
                await ctx.send("Ce challenge n'existe pas.")
                return False

    else:
        if box:
            if str(ctx.channel.type) == "private":
                await ctx.send("Tu n'as pas oublié quelque chose ?")
            else:
                box_name = ctx.channel.name.lower()
                box_status = htbot.check_box(box_name)
                if box_status:
                    status = trio_run(functools.partial(htbot.work_on, box_name, ctx.author.id, box=True))
                    if not status:
                        print("Erreur.")
                        return False
                    elif status == "success":
                        await ctx.send("Bonne chance {} ! ❤".format(ctx.author.mention))
                        return True
                    elif status == "already_owned":
                        await ctx.send("Tu as déjà terminé cette box !")
                        return True
                else:
                    await ctx.send("Tu n'as pas oublié quelque chose ?")

        elif chall:
            await ctx.send("Tu n'as pas oublié quelque chose ?")


@bot.command()
async def account(ctx, arg, action=""):
    """Manage your HTB account on the Discord server"""

@bot.command()
async def writeup(ctx, *, content=""):
    """Download box writeups"""

    wp_legit = cfg.options["writeup_legit"]

    async def fetch_writeup(ctx, box_name=""):
        if htbot.is_vip:
            if wp_legit:
                vip = htbot.check_member_vip(ctx.author.id)
                if vip == "not_sync":
                    await ctx.send("Vous n'avez pas synchronisé votre compte HTB.\nVoir : **>man verify**")
                    return False
                if vip == "free":
                    await ctx.send("Vous n'êtes pas VIP, vous n'avez donc pas accès aux writeups.\nMais vous pouvez néanmoins afficher les writeups soumis par les membres ! Voir : **>man writeup**")
                    return False

            msg = await ctx.send("Téléchargement du writeup...")
            wp = await LOOP.run_in_executor(THREADS["writeup_dl"], trio_run, htbot.writeup, box_name)
            await msg.edit(content="Upload du writeup...")
            if wp:
                if wp_legit:
                    await ctx.author.send("{} Voici le writeup de {} ! Bonne lecture 📖".format(ctx.author.mention, box_name.capitalize()), file=wp)
                    if not str(ctx.channel.type) == "private":
                        await ctx.send("{} Le writeup vous a été envoyé en message privé ! 😉".format(ctx.author.mention))
                else:
                    await ctx.send("{} Voici le writeup de {} ! Bonne lecture 📖".format(ctx.author.mention, box_name.capitalize()), file=wp)
                await msg.delete()
            else:
                await ctx.send("Erreur.")
        else:
            await ctx.send("L'hôte du bot n'est pas VIP, il est donc impossible de télécharger les writeups.\nVous pouvez néanmoins afficher les writeups soumis par les membres ! Voir : **>man writeup**")

    async def fetch_writeup_links(ctx, box_name, page):
        if page <= 0:
            await ctx.send("Bien essayé.")
            return False

        msg = await ctx.send("🔍 Je cherche les writeups...")
        links = await LOOP.run_in_executor(THREADS["writeup_links"], trio_run, functools.partial(htbot.writeup, box_name, links=True, page=page))
        await msg.delete()
        if links:
            if links["status"] == "found":
                await ctx.send(embed=links["embed"])
            elif links["status"] == "too_high":
                await ctx.send("Vous avez atteint la limite des pages disponibles.")
            elif links["status"] == "empty":
                await ctx.send("Aucun writeup de membre n'a été trouvé !")
        else:
            await ctx.send("Erreur.")

    # Args parser
    args = content.split()
    count = 0
    links = False
    page = None
    box_name = ""
    while count < len(args):
        if args[count] == "-links":
            links = True
            count += 1
            continue
        elif args[count] == "-page":
            try:
                int(args[count + 1])
            except (ValueError, IndexError):
                await ctx.send("Erreur.")
                return False
            else:
                page = int(args[count + 1])
                count += 2
                continue
        else:
            box_name = args[count]
            count += 1
            continue
        break

    if page and not links:
        await ctx.send("Erreur.")
        return False
    elif links and not page:
        page = 1

    if box_name:
        check = htbot.check_box(box_name)
        if check:
            if check == "retired":
                if links:
                    await fetch_writeup_links(ctx, box_name, page=page)
                else:
                    await fetch_writeup(ctx, box_name)
            elif check == "active":
                await ctx.send("La box est encore active, bien essayé petit chenapan 😏")

        else:
            await ctx.send("🤔 Tu es sûr que le nom de la box est correcte ?")

    else:
        if str(ctx.channel.type) == "private":
            await ctx.send("Tu n'as pas précisé la box.")
        else:
            box_name = ctx.channel.name.lower()
            check = htbot.check_box(box_name)
            if check == "retired":
                if links:
                    await fetch_writeup_links(ctx, box_name, page=page)
                else:
                    await fetch_writeup(ctx, box_name)
            elif check == "active":
                await ctx.send("La box est encore active, bien essayé petit chenapan 😏")

            else:
                await ctx.send("Tu n'as pas précisé la box.")

@bot.command()
async def ippsec(ctx, *, content=""):
    """Search through Ippsec videos"""

    async def search(ctx, content, page):
        if page <= 0:
            await ctx.send("Bien essayé.")
            return False

        results = htbot.ippsec(search=content, page=page)
        if results["status"] == "found":
            await ctx.send(embed=results["embed"])
        elif results["status"] == "too_high":
            await ctx.send("Vous avez atteint la limite des pages disponibles.")
        elif results["status"] == "not_found":
            await ctx.send("Aucun résultat !")

    # Args parser
    args = content.split()
    count = 0
    page = 1
    query = []
    search_flag = False

    while count < len(args):
        if args[count] == "-page":
            try:
                int(args[count + 1])
            except (ValueError, IndexError):
                await ctx.send("Erreur.")
                return False
            else:
                page = int(args[count + 1])
                count += 2
                if search_flag:
                    break
                continue
        else:
            search_flag = True
            query.append(args[count])
            count += 1

    query = " ".join(query)
    await search(ctx, query, page=page)

@bot.command()
async def progress(ctx, *, content=""):
    """Get members progress on a box / challenge"""

    async def make_embed(ctx, target, box=False, chall=False):
        guilds = bot.guilds
        bot_guild = False
        for guild in guilds:
            if guild.name == cfg.discord['guild_name']:
                bot_guild = guild

        if not bot_guild:
            await ctx.send("Erreur.")
            return False

        if box:

            box = trio_run(functools.partial(htbot.get_progress, target, box=True))
            embed = discord.Embed(title="Progress | " + box["name"], color=0x9acc14)
            embed.set_thumbnail(url=box["thumbnail"])

            working_on = ""
            if box["working_on"]:
                for user in box["working_on"]:
                    discord_user = bot_guild.get_member(user)
                    working_on += discord_user.display_name + "\n"
            else:
                working_on = "*Nobody*"

            embed.add_field(name="Working on", value=working_on)

            user_owns = ""
            if box["user_owns"]:
                for user in box["user_owns"]:
                    discord_user = bot_guild.get_member(user)
                    user_owns += discord_user.display_name + "\n"
            else:
                user_owns = "*Nobody*"

            embed.add_field(name="User", value=user_owns)

            root_owns = ""
            if box["root_owns"]:
                for user in box["root_owns"]:
                    discord_user = bot_guild.get_member(user)
                    root_owns += discord_user.display_name + "\n"
            else:
                root_owns = "*Nobody*"

            embed.add_field(name="Root", value=root_owns)

            return embed

        elif chall:
            chall = trio_run(functools.partial(htbot.get_progress, target, chall=True))
            embed = discord.Embed(title="Progress | {} ({})".format(chall["name"], chall["category"]), color=0x9acc14)

            working_on = ""
            if chall["working_on"]:
                for user in chall["working_on"]:
                    discord_user = bot_guild.get_member(user)
                    working_on += discord_user.display_name + "\n"
            else:
                working_on = "*Nobody*"

            embed.add_field(name="Working on", value=working_on)

            chall_owns = ""
            if chall["chall_owns"]:
                for user in chall["chall_owns"]:
                    discord_user = bot_guild.get_member(user)
                    chall_owns += discord_user.display_name + "\n"
            else:
                chall_owns = "*Nobody*"

            embed.add_field(name="Owns", value=chall_owns)

            return embed

    # Args parser
    args = content.split()
    count = 0
    box = False
    chall = False
    query = []
    target_flag = False

    while count < len(args):
        if (args[count] == "-b" or args[count] == "--box") and not box:
            box = True
            if target_flag:
                break
            else:
                count += 1
                continue

        elif (args[count] == "-c" or args[count] == "--chall") and not chall:
            chall = True
            if target_flag:
                break
            else:
                count += 1
                continue

        else:
            if not target_flag:
                target_flag = True
            query.append(args[count])
            count += 1

    if (box and chall) or (not box and not chall):
        await ctx.send("Erreur.")
        return False

    target = " ".join(query)

    if target:
        if box:
            box_status = htbot.check_box(target)
            if box_status:
                progress_stats = await make_embed(ctx, target, box=True)
                await ctx.send("", embed=progress_stats)
            else:
                await ctx.send("Cette box n'existe pas.")
        elif chall:
            chall_status = htbot.check_chall(target)
            if chall_status:
                progress_stats = await make_embed(ctx, target, chall=True)
                await ctx.send("", embed=progress_stats)
            else:
                await ctx.send("Ce challenge n'existe pas.")

    else:
        if str(ctx.channel.type) == "private":
            if box:
                await ctx.send("Tu n'as pas précisé la box.")
            elif chall:
                await ctx.send("Tu n'as pas précisé le challenge.")
        else:
            if box:
                box_name = ctx.channel.name.lower()
                box_status = htbot.check_box(box_name)
                if box_status:
                    progress_stats = await make_embed(ctx, box_name, box=True)
                    await ctx.send("", embed=progress_stats)
                else:
                    await ctx.send("Tu n'as pas précisé la box.")

            elif chall:
                await ctx.send("Tu n'as pas précisé le challenge.")


@bot.command()
async def get_chall(ctx, *, name=""):
    """Get info on a chall"""
    if name:
        chall_status = htbot.check_chall(name)
        if chall_status:
            chall = trio_run(htbot.get_chall, name)
            if chall:
                await ctx.send("", embed=chall["embed"])
            else:
                await ctx.send("Erreur.")
        else:
            await ctx.send("Ce challenge n'existe pas.")
    else:
        await ctx.send("Tu n'as pas précisé le challenge.")


@bot.command()
async def man(ctx, command=""):
    """Here is the fucking manual"""

    if command == "man" or not command:
        embed = discord.Embed(color=0x9acc14, title="📖  >man", description="""
        ***voir comment une commande fonctionne***

        **ARGS**
        {command} | *la commande sur laquelle tu veux avoir des informations*

        **EXAMPLES**
        >man account
        >man get_box
        """)

    elif command == "account":
        embed = discord.Embed(color=0x9acc14, title="📖  >account", description="""
        ***gère la synchronisation Hack The Box***

        **PARAMS**
        -mention on/off | *si le bot te mentionne dans la shoutbox ou non*
        -private on/off | *si le bot envoie une notif de ton pwn dans la shoutbox ou non*
        -forget confirm | *si tu veux arrêter la synchro Discord / HTB*
        -verify | *commencer à synchroniser ton compte HTB avec le serveur*

        **EXAMPLES**
        >account -mention off
        >account -forget confirm
        """)

    elif command == "get_box":
        embed = discord.Embed(color=0x9acc14, title="📖  >get_box", description="""
        ***récupère les informations sur une box***

        **ARGS**
        {box_name} | *le nom de la box*

        **PARAMS**
        -matrix | *plus long, mais envoie la matrix avec*

        **EXAMPLES**
        >get_box forest
        >get_box registry -matrix
        """)

    elif command == "last_box":
        embed = discord.Embed(color=0x9acc14, title="📖  >last_box", description="""
        ***récupère les informations de la dernière box***

        **PARAMS**
        -matrix | *plus long, mais envoie la matrix avec*

        **EXAMPLES**
        >last_box
        >last_box -matrix
        """)

    elif command == "me":
        embed = discord.Embed(color=0x9acc14, title="📖  >me", description="""
        ***affiche tes infos HTB***

        **EXAMPLES**
        >me
        """)

    elif command == "get_user":
        embed = discord.Embed(color=0x9acc14, title="📖  >get_user", description="""
        ***affiche les infos d'un membre HTB***

        **ARGS**
        {user} | *le nom du membre*

        **EXAMPLES**
        >get_user mxrch
        """)

    elif command == "leaderboard":
        embed = discord.Embed(color=0x9acc14, title="📖  >leaderboard", description="""
        ***envoie le classement des membres du serveur***

        **EXAMPLES**
        >leaderboard
        """)

    elif command == "list_boxes":
        embed = discord.Embed(color=0x9acc14, title="📖  >list_boxes", description="""
        ***liste les boxs actives par difficulté ou non***

        **ARGS**
        easy/medium/hard/insane | *la difficulté*

        **EXAMPLES**
        >list_boxes
        >list_boxes hard
        """)

    elif command == "hello":
        embed = discord.Embed(color=0x9acc14, title="📖  >hello", description="""
        ***affiche Hello World !***

        **EXAMPLES**
        >hello
        """)

    elif command == "echo":
        embed = discord.Embed(color=0x9acc14, title="📖  >echo", description="""
        ***fait le perroquet***

        **ARGS**
        {text} | *texte à répéter*

        **EXAMPLES**
        >echo 123
        >echo hello world
        """)

    elif command == "ping":
        embed = discord.Embed(color=0x9acc14, title="📖  >ping", description="""
        ***calcule le temps de réponse du bot***

        **EXAMPLES**
        >ping
        """)

    elif command == "writeup":
        embed = discord.Embed(color=0x9acc14, title="📖  >writeup", description="""
        ***envoie le ou les writeups d'une box***

        **ARGS**
        {box_name} | *le nom de la box*

        **PARAMS**
        -links | *envoie les writeups publiés par les membres plutôt que l'officiel*
        -page {page} | *la page de la liste des writeups*

        **EXAMPLES**
        >writeup hackback
        >writeup heist -links -page 4
        """)

    elif command == "help":
        embed = discord.Embed(color=0x9acc14, title="📖  >help", description="""
        ***liste toutes les commandes avec leur description***

        **EXAMPLES**
        >help
        """)

    elif command == "work_on":
        embed = discord.Embed(color=0x9acc14, title="📖  >work_on", description="""
        ***annonce que vous commencez une box, et créé le channel dédié s'il n'existe pas encore***

        **ARGS**
        {box_name} | *le nom de la box*

        **EXAMPLES**
        >work_on
        >work_on monteverde
        """)

    elif command == "ippsec":
        embed = discord.Embed(color=0x9acc14, title="📖  >ippsec", description="""
        ***cherche des mots-clés dans les vidéos d'Ippsec***

        **ARGS**
        {query} | *la recherche*

        **PARAMS**
        -page {page} | *la page des résultats*

        **EXAMPLES**
        >ippsec gobuster
        >ippsec bitlab -page 4
        >ippsec -page 2 active directory
        """)

    else:
        await ctx.send("🤔 Je ne connais pas cette commande !")
        return False

    await ctx.send(embed=embed)


bot.run(cfg.discord['bot_token'])
