# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Uptime Sentinel v3 — full alerting, cooldowns, per-endpoint metadata - formally uptime_pinger
import sys, os

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import time, requests
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):

    def __init__(self):
        super().__init__()

        cfg = self.tree_node.get("config", {}) or {}

        # Each entry = { "url": "...", "note": "immutable text" }
        self.targets = cfg.get("targets", [])

        # global ping interval
        self._interval = cfg.get("interval_sec", 30)

        self._emit_beacon = self.check_for_thread_poke("worker", timeout=self._interval * 6, emit_to_file_interval=10)

        # send alerts to a Phoenix role (discord, email, etc.)
        self.alert_role = cfg.get("alert_to_role", "hive.alert")

        # cool-down per endpoint
        self.cooldown = int(cfg.get("cooldown", 300))

        # maintain last state
        self._last_state = {}       # url → { "success": bool, "ts": float }
        self._last_alert = {}       # url → timestamp of last alert

        # log state timeouts
        self.log_every = int(cfg.get("log_every", 300))  # seconds between routine summary logs
        self.only_log_state_changes = bool(cfg.get("only_log_state_changes", False))
        self._last_log_time = 0

        self.log(f"[UPTIME] Online with {len(self.targets)} targets — interval={self._interval}s cooldown={self.cooldown}s")

    # -------------------------------------------------------
    def worker(self, config=None, identity:IdentityObject=None):
        """Main worker function handling file monitoring and taking actions."""
        if not self.running:
            return

        self._run_cycle()

        self._emit_beacon()
        interruptible_sleep(self, self._interval)


    # -------------------------------------------------------
    def _run_cycle(self):

        now = time.time()
        # Show all endpoints being watched on first cycle
        if not self._last_state:
            self.log("[UPTIME] 🔍 Initial scan – watching the following endpoints:")
            for t in self.targets:
                self.log(f"   • {t.get('url')}  ({t.get('note', '')})  expect='{t.get('expect', '')}'")

        for entry in self.targets:
            url = entry.get("url")
            note = entry.get("note", "")
            expect = entry.get("expect", "")

            if not url:
                continue

            start = time.time()
            ok = False
            status = None

            try:
                r = requests.get(url, timeout=6)
                ok = r.ok
                status = r.status_code
                elapsed = time.time() - start
                body = r.text
            except Exception as e:
                ok = False
                status = "ERR"
                elapsed = 0.0
                body = ""

            if not self.only_log_state_changes:
                self.log(f"[UPTIME] {url} → {status} in {elapsed:.2f}s")

            expect = entry.get("expect", "").strip()
            self._evaluate(url, ok, status, elapsed, note, expect, body, now)

        # --- Periodic heartbeat log ---
        if not self.only_log_state_changes:
            now = time.time()
            if now - self._last_log_time >= self.log_every:
                self._last_log_time = now
                nxt = time.strftime('%H:%M:%S', time.gmtime(self.log_every))
                self.log(f"[UPTIME] 🕒 Next full report in {nxt} (every {self.log_every}s).")


    # -------------------------------------------------------
    def _evaluate(self, url, ok, status, elapsed, note, expect, body, now):
        prev = self._last_state.get(url)
        last_alert = self._last_alert.get(url, 0)

        # If an expected text is declared, verify it is present
        if expect:
            text_ok = expect in body
            if ok and not text_ok:
                ok = False
                status = f"MISMATCH (missing '{expect}')"

        # first time seen
        if prev is None:
            self._last_state[url] = {"success": ok, "ts": now}
            if not ok:
                self._send_alert(url, status, elapsed, note, expect, "DOWN", now)
            return

        # previously success
        if prev["success"] and not ok:
            # DOWN event
            if now - last_alert >= self.cooldown:

                if self.only_log_state_changes:
                    self.log(f"[UPTIME][STATE] {url} changed → {'UP' if ok else 'DOWN'} ({status})")
                self._send_alert(url, status, elapsed, note, expect, "DOWN", now)
            self._last_state[url] = {"success": False, "ts": now}
            return

        # previously fail → now success
        if not prev["success"] and ok:
            if self.only_log_state_changes:
                self.log(f"[UPTIME][STATE] {url} changed → {'UP' if ok else 'DOWN'} ({status})")
            self._send_alert(url, status, elapsed, note, expect, "RECOVERY", now)
            self._last_state[url] = {"success": True, "ts": now}
            return

        # still down, but cooldown expired → repeat alert
        if not ok and (now - last_alert >= self.cooldown):
            if self.only_log_state_changes:
                self.log(f"[UPTIME][STATE] {url} changed → {'UP' if ok else 'DOWN'} ({status})")
            self._send_alert(url, status, elapsed, note, expect, "DOWN", now)
            self._last_state[url] = {"success": False, "ts": now}
            return

        # no change → no action
        self._last_state[url] = {"success": ok, "ts": now}

    # -------------------------------------------------------
    def _send_alert(self, url, status, elapsed, note, expect, event_type, now):
        """
        Build a full alert packet and dispatch it to alert_role.
        """
        self._last_alert[url] = now

        try:
            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                self.log(f"[UPTIME][ALERT] No endpoints for role={self.alert_role}", level="WARN")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk2 = self.get_delivery_packet("notify.alert.general")

            if event_type == "DOWN":
                level = "critical"
                icon = "🔻"
            elif event_type == "RECOVERY":
                level = "success"
                icon = "🔺"
            else:
                level = "info"
                icon = "ℹ️"

            msg = (
                f"{icon} Uptime Alert — {event_type}\n\n"
                f"• URL: {url}\n"
                f"• Status: {status}\n"
                f"• Response Time: {elapsed:.2f}s\n"
                f"• Note: {note}\n"
            )

            if expect:
                msg += f"• Expected Text: '{expect}'\n"

            if expect and event_type == "DOWN":
                msg += "• Reason: Expected text was NOT found in page response.\n"

            msg += f"• Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}"

            pk2.set_data({
                "msg": msg,
                "level": level,
                "origin": self.command_line_args.get("universal_id", "uptime_pinger"),
                "cause": "Uptime Monitor"
            })

            pk1.set_packet(pk2, "content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

            self.log(f"[UPTIME][ALERT] {event_type}: {url}")

        except Exception as e:
            self.log("[UPTIME][ALERT][ERROR]", error=e)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()