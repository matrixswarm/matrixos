# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys
import os
import time
import json
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
# ╔══════════════════════════════════════════════════════════╗
# ║                  📡 DISCORD AGENT V3 📡                  ║
# ║     Matrix-Compatible · Swarm Speaker · Relay-Class     ║
# ╚══════════════════════════════════════════════════════════╝

import threading
import discord as discord_real
from discord.ext import commands
import asyncio

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    def __init__(self):
        super().__init__()

        self.discord_client = None
        self.bot = None

        # Inject full tree_node so BootAgent sees config
        self.directives = self.tree_node
        self.interval=60
        self.inbox_paths=['incoming']
        path = os.path.join(self.path_resolution["comm_path_resolved"], "incoming")
        os.makedirs(path, exist_ok=True)
        self.inbox_paths.append(path)

        # Local config for this agent
        config = self.directives.get("config", {})
        discord = config.get("discord", {}) or config
        self.token = discord.get("bot_token")
        channel_id = discord.get("channel_id")
        if channel_id is not None:
            self.channel_id = int(channel_id)
        else:
            self.channel_id = 0
        self.name = "DiscordAgentV3e"
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)

    def post_boot(self):
        self.log("[DISCORD] Starting client runner thread...")
        self._discord_thread = threading.Thread(target=self._discord_runner, name="discord-runner", daemon=True)
        self._discord_thread.start()

    def _discord_runner(self):
        """
        Runs the discord event loop in a single thread. Saves the loop and bot
        so worker() can schedule shutdown and call loop.stop() safely.
        """
        try:
            # create and set loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._discord_loop = loop

            intents = discord_real.Intents.default()
            intents.messages = True
            intents.message_content = True

            self.bot = commands.Bot(command_prefix="!", intents=intents)

            # create the beacon writer for the discord loop
            self.emit_discord_beacon = self.check_for_thread_poke("discord_client", timeout=30, emit_to_file_interval=10)

            async def heartbeat_task():
                while self.running and not loop.is_closed():
                    self.emit_discord_beacon()
                    await asyncio.sleep(10)

            @self.bot.event
            async def on_ready():
                self.log(f"[DISCORD] Connected as {self.bot.user}")
                try:
                    channel = await self.bot.fetch_channel(self.channel_id)
                    await channel.send("DiscordAgent V3e online and responding.")
                except Exception as e:
                    self.log(f"[DISCORD][WARN] Channel access failed: {e}")

            async def start_and_wait():
                # schedule heartbeat and start bot
                loop.create_task(heartbeat_task())
                await self.bot.start(self.token)

            # run the bot until stopped
            loop.run_until_complete(start_and_wait())

        except Exception as e:
            self.log(f"[DISCORD][ERROR] Discord runner crashed: {e}")
        finally:
            # cleanup if loop alive
            try:
                if hasattr(self, "bot") and self.bot and not loop.is_closed():
                    # best-effort close
                    try:
                        loop.run_until_complete(self.bot.close())
                    except Exception:
                        pass
                if not loop.is_closed():
                    loop.close()
            except Exception:
                pass
            self.log("[DISCORD] discord runner thread exiting.")

    def worker_pre(self):
        self.log("[DISCORD] Worker alive, idling.")


    def cmd_send_alert_msg(self, content: dict, packet, identity: IdentityObject = None):
        """
        Receives a unified alert packet and renders the best format available.
        """
        # Check if rich embed data exists
        if content.get("embed_data"):
            # Use the new logic to send a rich embed
            self.send_embed_from_data(content["embed_data"])
        else:
            # Fall back to sending plain text for older/simpler alerts
            message_to_send = content.get("formatted_msg") or content.get("msg") or "[SWARM] No content."
            self.send_text_message(message_to_send)

    def send_text_message(self, message: str):
        try:
            self.send_to_discord(message)
            self.log("[DISCORD] Message relayed successfully.")
        except Exception as e:
            self.log(f"[DISCORD][ERROR] Failed to relay message: {e}")

    def send_to_discord(self, message):
        if not self.bot or not self.channel_id:
            self.log("[DISCORD][ERROR] Bot not ready or channel ID missing.")
            return
        try:
            channel = self.bot.get_channel(self.channel_id)
            if channel:
                asyncio.run_coroutine_threadsafe(channel.send(message), self.bot.loop)
            else:
                self.log("[DISCORD][ERROR] Channel not found.")
        except Exception as e:
            self.log(f"[DISCORD][ERROR] Discord delivery failed: {e}")

    def send_embed_from_data(self, content: dict):
        """
        Receives embed data and renders it in a Discord channel.
        This method replaces the old cmd_send_alert_msg.
        """
        if not self.bot or not self.channel_id:
            self.log("[DISCORD][ERROR] Bot not ready or channel ID missing.")
            return

        try:
            # Convert color string to a discord.Color object, default to blurple
            color_str = content.get("color", "blurple")
            color_obj = getattr(discord_real.Color, color_str, discord_real.Color.default)()

            # Create the embed object directly from the packet's content
            embed = discord_real.Embed(
                title=content.get("title", "Swarm Alert"),
                description=content.get("description", "No details provided."),
                color=color_obj
            )
            embed.set_footer(text=content.get("footer", ""))

            # Send the embed
            channel = self.bot.get_channel(self.channel_id)
            if channel:
                asyncio.run_coroutine_threadsafe(channel.send(embed=embed), self.bot.loop)
            else:
                self.log(f"[DISCORD][ERROR] Channel {self.channel_id} not found.")

        except Exception as e:
            self.log(f"[DISCORD][ERROR] Failed to send embed: {e}")
            import traceback
            traceback.print_exc()

    def format_message(self, data: dict):
        """Builds a detailed message from embed_data if present."""
        return data.get("formatted_msg") or data.get("msg") or "[SWARM] No content."

    #SEND A NON SPAMMING MESSAGE TO DISCORD TO BE RETRIEVED AT THE CONVENIENCE OF PHOENIX
    def _send_text_message(self, message: str, tag: str = "SWARM_PAYLOAD", ttl_seconds: int = 3600):
        try:
            loop = self.bot.loop
            channel = self.bot.get_channel(self.channel_id)
            if not channel:
                self.log("[DISCORD][ERROR] Channel not found.")
                return

            async def controlled_delivery():
                # Step 1: Fetch last 10 messages from channel
                messages = await channel.history(limit=10).flatten()
                for msg in messages:
                    if tag in msg.content and msg.author == self.bot.user:
                        try:
                            payload_block = msg.content.split("```json")[1].split("```")[0]
                            payload = json.loads(payload_block)
                            # Step 2: Check TTL
                            ts = payload.get("meta", {}).get("timestamp")
                            ttl = payload.get("meta", {}).get("ttl")
                            if ts and ttl:
                                expire_at = ts + ttl
                                if time.time() > expire_at:
                                    await msg.delete()
                                else:
                                    self.log("[DISCORD] Skipping resend: active payload already exists.")
                                    return
                            else:
                                await msg.delete()  # Legacy/no-meta? Remove it.
                        except Exception as e:
                            self.log(f"[DISCORD][WARN] Message parse failed: {e}")
                            await msg.delete()

                # Step 3: Send new message
                swarm_payload = {
                    "payload": message,
                    "meta": {
                        "swarm_id": self.name,
                        "timestamp": int(time.time()),
                        "ttl": ttl_seconds
                    }
                }
                encoded = json.dumps(swarm_payload, indent=2)
                formatted = f"{tag}\n```json\n{encoded}\n```"
                await channel.send(formatted)
                self.log("[DISCORD] Payload relayed with TTL + swarm tag.")

            asyncio.run_coroutine_threadsafe(controlled_delivery(), loop)

        except Exception as e:
            self.log(f"[DISCORD][ERROR] Controlled delivery failed: {e}")

    async def count_messages(self, days=1):
        cutoff = time.time() - (days * 86400)
        channel = self.bot.get_channel(self.channel_id)
        count = 0
        async for msg in channel.history(limit=None):
            if msg.created_at.timestamp() > cutoff:
                count += 1
        return count

    async def _async_shutdown_bot(self):
        # coroutine to close bot (call from main thread via run_coroutine_threadsafe)
        if self.bot:
            try:
                await self.bot.close()
            except Exception as e:
                self.log(f"[DISCORD][WARN] bot.close() error: {e}")

    def _stop_discord_loop(self):
        """
        Stop the discord event loop from another thread safely.
        """
        if getattr(self, "_discord_loop", None) and not self._discord_loop.is_closed():
            try:
                # schedule loop.stop() from the loop thread
                self._discord_loop.call_soon_threadsafe(self._discord_loop.stop)
            except Exception as e:
                self.log(f"[DISCORD][WARN] Failed to stop discord loop: {e}")


    def worker(self, config=None, identity=None):
        """
        Called by _throttled_worker_wrapper repeatedly. On shutdown we:
          - schedule coroutine to close the bot
          - ask the event loop to stop
          - join the thread (with timeout)
        """
        # regular heartbeat from worker so Phoenix shows agent live
        if self.running:
            # normal operation — worker emits a beacon too (fast path)
            # keep short sleep so die.cookie is responsive
            self._emit_beacon()
            interruptible_sleep(self, 2)
            return

        # we are shutting down: request the discord loop to close gracefully
        self.log("[DISCORD] Shutdown requested from worker loop. Initiating graceful stop.")

        try:
            if getattr(self, "_discord_loop", None):
                # schedule the async shutdown from the main thread
                fut = asyncio.run_coroutine_threadsafe(self._async_shutdown_bot(), self._discord_loop)
                # wait briefly for the coroutine to complete
                try:
                    fut.result(timeout=5)
                except Exception:
                    # shutdown coroutine hung — still attempt to stop loop
                    pass

                # ask the loop to stop (will break run_forever)
                self._stop_discord_loop()

            # wait for the runner thread to exit — conservative timeout
            if getattr(self, "_discord_thread", None) and self._discord_thread.is_alive():
                self.log("[DISCORD] Waiting up to 5s for discord runner thread to exit...")
                self._discord_thread.join(timeout=5)
        except Exception as e:
            self.log(f"[DISCORD][WARN] shutdown sequence error: {e}")

        # final short sleep to allow wrapper to exit
        interruptible_sleep(self, 0.5)

def cmd_cleanup_messages(self, content, packet=None, identity=None):
    """
    Phoenix-triggered cleanup command.
    Deletes past messages sent by the bot in the configured channel.

    Optional fields in content:
    - tag: filter messages that start with this tag (e.g., "SWARM_PAYLOAD")
    - ttl_only: if True, only delete messages with expired TTL (meta.timestamp + meta.ttl)
    """
    tag = content.get("tag")
    ttl_only = content.get("ttl_only", False)

    async def _clean():
        channel = self.bot.get_channel(self.channel_id)
        if not channel:
            self.log("[DISCORD][ERROR] Channel not found for cleanup.")
            return

        deleted = 0
        async for msg in channel.history(limit=100):
            if msg.author != self.bot.user:
                continue

            if tag and not msg.content.startswith(tag):
                continue

            try:
                if ttl_only:
                    # Try to extract TTL info
                    payload_block = msg.content.split("```json")[1].split("```")[0]
                    payload = json.loads(payload_block)
                    ts = payload.get("meta", {}).get("timestamp")
                    ttl = payload.get("meta", {}).get("ttl")
                    if ts and ttl and (time.time() < ts + ttl):
                        continue  # Not expired
                await msg.delete()
                deleted += 1
            except Exception as e:
                self.log(f"[DISCORD][WARN] Could not delete msg: {e}")

        self.log(f"[DISCORD] Cleanup complete. {deleted} messages deleted.")

    asyncio.run_coroutine_threadsafe(_clean(), self.bot.loop)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
