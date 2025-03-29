import os
import discord
from discord.ext import commands, tasks
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

# Security configurations
MAX_CHANNEL_CREATIONS = 1
MAX_ROLE_CREATIONS = 1
MAX_BAN_ATTEMPTS = 1
MAX_KICK_ATTEMPTS = 1
MAX_DELETIONS = 1
ALERT_CHANNEL_NAME = "security-logs"
BOT_INVITE_PROTECTION = True

intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

# Track original permissions and suspicious activity
original_permissions = {}
user_activity = {}
whitelisted_users = set()  # Store whitelisted user IDs

async def backup_permissions(guild):
    """Backup current permissions before making changes"""
    original_permissions[guild.id] = {
        'everyone': guild.default_role.permissions,
        'channels': {
            channel.id: channel.overwrites for channel in guild.text_channels
        }
    }

async def restore_permissions(guild):
    """Restore original permissions"""
    if guild.id not in original_permissions:
        return False
    
    try:
        # Restore @everyone permissions
        await guild.default_role.edit(
            permissions=original_permissions[guild.id]['everyone']
        )
        
        # Restore channel-specific permissions
        for channel in guild.text_channels:
            if channel.id in original_permissions[guild.id]['channels']:
                await channel.edit(sync_permissions=True)
                for target, overwrite in original_permissions[guild.id]['channels'][channel.id].items():
                    await channel.set_permissions(target, overwrite=overwrite)
        
        return True
    except Exception as e:
        print(f"Restore failed: {e}")
        return False

async def get_alert_channel(guild):
    """Get or create the alert channel"""
    try:
        alert_channel = discord.utils.get(guild.text_channels, name=ALERT_CHANNEL_NAME)
        if not alert_channel:
            overwrites = {
                guild.default_role: discord.PermissionOverwrite(read_messages=False),
                guild.me: discord.PermissionOverwrite(read_messages=True)
            }
            alert_channel = await guild.create_text_channel(
                ALERT_CHANNEL_NAME,
                overwrites=overwrites,
                reason="Security alert channel"
            )
        return alert_channel
    except Exception as e:
        print(f"Error getting alert channel: {e}")
        return None

async def handle_suspicious_action(guild, user, action_type, target=None):
    """Process suspicious actions with auto-unlock"""
    if user.id == guild.owner_id or user.id in whitelisted_users or user.top_role >= guild.me.top_role:
        return  # Ignore actions from server owner, whitelisted users, or users with higher roles

    alert_channel = await get_alert_channel(guild)
    try:
        # Send alert
        if alert_channel:
            embed = discord.Embed(
                title="🚨 Suspicious Activity Detected",
                description=f"Action: {action_type.replace('_', ' ').title()}",
                color=discord.Color.red()
            )
            embed.add_field(name="User", value=f"{user.mention} ({user.id})")
            await alert_channel.send(embed=embed)
    
        # Delete suspicious channels/roles
        if target and action_type.endswith("_create"):
            try:
                await target.delete(reason="Suspicious creation")
            except:
                pass
    except Exception as e:
        print(f"Error handling suspicious action: {e}")

@bot.event
async def on_guild_channel_create(channel):
    async for entry in channel.guild.audit_logs(action=discord.AuditLogAction.channel_create, limit=1):
        if entry.target.id == channel.id:
            await handle_suspicious_action(channel.guild, entry.user, "channel_create", channel)
            break

@bot.event
async def on_guild_role_create(role):
    async for entry in role.guild.audit_logs(action=discord.AuditLogAction.role_create, limit=1):
        if entry.target.id == role.id:
            await handle_suspicious_action(role.guild, entry.user, "role_create", role)
            break

@bot.event
async def on_member_join(member):
    if member.id == bot.user.id and BOT_INVITE_PROTECTION:
        async for entry in member.guild.audit_logs(action=discord.AuditLogAction.bot_add, limit=1):
            await handle_suspicious_action(member.guild, entry.user, "bot_add")
            break

@tasks.loop(minutes=30)
async def cleanup_activity():
    """Clean up old activity records"""
    global user_activity
    now = datetime.now(timezone.utc)
    user_activity = {
        user: {act: data for act, data in acts.items() 
              if now - data['timestamp'] < timedelta(hours=1)}
        for user, acts in list(user_activity.items())
    }

@bot.event
async def on_ready():
    print(f'Security bot {bot.user.name} is online!')
    cleanup_activity.start()
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="for suspicious activity"
    ))

# Whitelist command (Only Server Owner Can Use It)
@bot.command(name='whitelist')
async def whitelist(ctx, member: discord.Member):
    if ctx.author.id != ctx.guild.owner_id:
        await ctx.send("❌ Only the server owner can whitelist users!")
        return
    
    whitelisted_users.add(member.id)
    await ctx.send(f"✅ {member.mention} has been whitelisted!")

# Unwhitelist command (Only Server Owner Can Use It)
@bot.command(name='unwhitelist')
async def unwhitelist(ctx, member: discord.Member):
    if ctx.author.id != ctx.guild.owner_id:
        await ctx.send("❌ Only the server owner can unwhitelist users!")
        return
    
    whitelisted_users.discard(member.id)
    await ctx.send(f"✅ {member.mention} has been removed from the whitelist!")

if __name__ == '__main__':
    try:
        bot.run(os.getenv('DISCORD_TOKEN'))
    except Exception as e:
        print(f"Fatal error: {e}")
