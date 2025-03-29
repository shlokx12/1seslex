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

async def secure_ban_and_restore(guild, user, reason):
    """Ban user and restore server permissions"""
    try:
        # First backup current permissions if not already done
        if guild.id not in original_permissions:
            await backup_permissions(guild)
        
        # Ban the user
        if user.top_role >= guild.me.top_role:
            return False, "User has higher role"
        
        await guild.ban(user, reason=reason)
        
        # Restore original permissions
        restore_success = await restore_permissions(guild)
        
        return True, f"Banned successfully. Server {'restored' if restore_success else 'restore failed'}"
    except Exception as e:
        return False, f"Error: {str(e)}"

async def handle_suspicious_action(guild, user, action_type, target=None):
    """Process suspicious actions with auto-unlock"""
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

        # Take action based on severity
        if action_type in ["channel_create", "role_create", "channel_delete", "role_delete", "bot_add"]:
            success, msg = await secure_ban_and_restore(guild, user, f"Suspicious: {action_type}")
            if alert_channel:
                await alert_channel.send(f"Action taken: {msg}")

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
    try:
        async for entry in channel.guild.audit_logs(action=discord.AuditLogAction.channel_create, limit=1):
            if entry.target.id == channel.id:
                await handle_suspicious_action(channel.guild, entry.user, "channel_create", channel)
                break
    except Exception as e:
        print(f"Error in channel_create: {e}")

@bot.event
async def on_guild_channel_delete(channel):
    try:
        async for entry in channel.guild.audit_logs(limit=1):
            if hasattr(entry.target, 'id') and entry.target.id == channel.id:
                await handle_suspicious_action(channel.guild, entry.user, "channel_delete")
                break
    except Exception as e:
        print(f"Error in channel_delete: {e}")

@bot.event
async def on_guild_role_create(role):
    try:
        async for entry in role.guild.audit_logs(action=discord.AuditLogAction.role_create, limit=1):
            if entry.target.id == role.id:
                await handle_suspicious_action(role.guild, entry.user, "role_create", role)
                break
    except Exception as e:
        print(f"Error in role_create: {e}")

@bot.event
async def on_guild_role_delete(role):
    try:
        async for entry in role.guild.audit_logs(limit=1):
            if hasattr(entry.target, 'id') and entry.target.id == role.id:
                await handle_suspicious_action(role.guild, entry.user, "role_delete")
                break
    except Exception as e:
        print(f"Error in role_delete: {e}")

@bot.event
async def on_member_ban(guild, user):
    try:
        async for entry in guild.audit_logs(action=discord.AuditLogAction.ban, limit=1):
            await handle_suspicious_action(guild, entry.user, "ban")
            break
    except Exception as e:
        print(f"Error in member_ban: {e}")

@bot.event
async def on_member_kick(guild, user):
    try:
        async for entry in guild.audit_logs(action=discord.AuditLogAction.kick, limit=1):
            await handle_suspicious_action(guild, entry.user, "kick")
            break
    except Exception as e:
        print(f"Error in member_kick: {e}")

@bot.event
async def on_member_join(member):
    if member.id == bot.user.id and BOT_INVITE_PROTECTION:
        try:
            async for entry in member.guild.audit_logs(action=discord.AuditLogAction.bot_add, limit=1):
                await handle_suspicious_action(member.guild, entry.user, "bot_add")
                break
        except Exception as e:
            print(f"Error in member_join: {e}")

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

# Manual unlock command for admins
@bot.command(name='unlock')
@commands.has_permissions(administrator=True)
async def manual_unlock(ctx):
    """Manually restore server permissions"""
    success = await restore_permissions(ctx.guild)
    if success:
        await ctx.send("✅ Server permissions restored")
    else:
        await ctx.send("❌ Failed to restore permissions")

if __name__ == '__main__':
    try:
        bot.run(os.getenv('DISCORD_TOKEN'))
    except Exception as e:
        print(f"Fatal error: {e}")