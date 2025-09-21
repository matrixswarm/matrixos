# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Docstrings by Gemini
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import subprocess
import time
import requests
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from datetime import datetime

from core.python_core.mixin.agent_summary_mixin import AgentSummaryMixin

class Agent(BootAgent, AgentSummaryMixin):
    def __init__(self):
        super().__init__()

        self.name = "RedisHammer"
        cfg = self.tree_node.get("config", {})
        self.interval = cfg.get("check_interval_sec", 10)
        self.service_name = cfg.get("service_name", "redis")
        self.redis_port = cfg.get("redis_port", 6379)
        self.socket_path = cfg.get("socket_path", "/var/run/redis/redis-server.sock")
        self.restart_limit = cfg.get("restart_limit", 3)
        self.always_alert = bool(cfg.get("always_alert", 1))
        self.alert_role = cfg.get("alert_to_role", None)
        self.report_role = cfg.get("report_to_role", None)  # Optional
        self.failed_restarts = 0
        self.disabled = False
        self.alerts = {}
        self.alert_cooldown = 600
        self.last_status = None
        self.stats = {
            "date": self.today(),
            "uptime_sec": 0,
            "downtime_sec": 0,
            "restarts": 0,
            "last_state": None,
            "last_change": time.time()
        }
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=self.interval*2, emit_to_file_interval=10)
        # test writing summary
        #self.stats["date"] = "1900-01-01"

    def today(self):
        return datetime.now().strftime("%Y-%m-%d")

    def is_redis_running(self):
        try:
            result = subprocess.run(["systemctl", "is-active", "--quiet", self.service_name], check=False)
            return result.returncode == 0
        except Exception as e:
            self.log(f"[HAMMER][ERROR] systemctl failed: {e}")
            return False

    def is_port_open(self):
        try:
            out = subprocess.check_output(["ss", "-ltn"])
            return f":{self.redis_port}".encode() in out
        except Exception:
            return False

    def is_socket_up(self):
        return os.path.exists(self.socket_path)

    def restart_redis(self):
        if self.disabled:
            self.log("[HAMMER] Watchdog disabled. Restart skipped.")
            return
        try:
            subprocess.run(["systemctl", "restart", self.service_name], check=True)
            self.log("[HAMMER] ✅ Redis successfully restarted.")
            self.failed_restarts = 0
            self.stats["restarts"] += 1
        except Exception as e:
            self.failed_restarts += 1
            self.log(f"[HAMMER][FAIL] Restart failed: {e}")
            if self.failed_restarts >= self.restart_limit:
                self.disabled = True
                self.alert_operator("redis-failout", "💀 Redis hammer disabled after repeated restart failures.")

    def update_stats(self, running):
        now = time.time()
        elapsed = now - self.stats["last_change"]
        if self.stats["last_state"] is not None:
            if self.stats["last_state"]:
                self.stats["uptime_sec"] += elapsed
            else:
                self.stats["downtime_sec"] += elapsed
        self.stats["last_state"] = running
        self.stats["last_change"] = now

    def should_alert(self, key):

        if self.always_alert:
            return True

        now = time.time()
        last = self.alerts.get(key, 0)
        if now - last > self.alert_cooldown:
            self.alerts[key] = now
            return True
        return False

    def alert_operator(self, message=None):

        try:

            if not message:
                message = "🚨 REDIS REFLEX TERMINATION\n\nReflex loop failed (exit_code = -1)"

            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                self.log(f"[WATCHDOG][ALERT] No alert-compatible agents found for '{self.alert_role}'.")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data({"handler": "dummy_handler"})

            try:
                server_ip = requests.get("https://api.ipify.org").text.strip()
            except Exception:
                server_ip = "Unknown"

            pk2 = self.get_delivery_packet("notify.alert.general")
            pk2.set_data({
                "server_ip": server_ip,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "universal_id": self.command_line_args.get("universal_id", "unknown"),
                "level": "critical",
                "msg": message,
                "formatted_msg": f"📣 Redis Watchdog\n{message}",
                "cause": "Redis Sentinel Alert",
                "origin": self.command_line_args.get("universal_id", "unknown")
            })

            pk1.set_packet(pk2, "content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def send_data_report(self, status, severity, details="", metrics=None):
        """Sends a structured data packet for analysis, with optional metrics."""

        try:
            if not self.report_role:
                return

            endpoints = self.get_nodes_by_role(self.report_role)
            if not endpoints:
                self.log(f"[WATCHDOG][ALERT] No report-compatible agents found for '{self.report_role}'.")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data({"handler": "cmd_ingest_status_report"})

            pk2 = self.get_delivery_packet("standard.status.event.packet")
            pk2.set_data({
                "source_agent": self.command_line_args.get("universal_id"),
                "service_name": "redis",
                "status": status,
                "details": details,
                "severity": severity,
                "metrics": metrics if metrics is not None else {}
            })

            pk1.set_packet(pk2, "content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def collect_redis_diagnostics(self):
        """
        Gathers Redis-specific diagnostics:
        - systemctl status
        - redis-cli INFO (if available)
        - error log tail
        """
        info = {}
        # systemd status
        try:
            info['systemd_status'] = subprocess.check_output(
                ["systemctl", "status", self.service_name],
                text=True, stderr=subprocess.STDOUT
            ).strip()
        except Exception as e:
            info['systemd_status'] = f"Error: {e}"

        # redis-cli info
        try:
            out = subprocess.check_output(["redis-cli", "info"], text=True, timeout=5)
            info['redis_info'] = out
        except Exception as e:
            info['redis_info'] = f"Error: {e}"

        # log tail
        for log_path in ["/var/log/redis/redis-server.log", "/var/log/redis/redis.log"]:
            if os.path.exists(log_path):
                try:
                    out = subprocess.check_output(["tail", "-n", "20", log_path], text=True)
                    info['error_log'] = out
                except Exception as e:
                    info['error_log'] = f"Error: {e}"
                break

        return info

    def worker(self, config:dict = None, identity:IdentityObject = None):

        try:
            self._emit_beacon()
            self.maybe_roll_day('redis')
            running = self.is_redis_running()
            accessible = self.is_port_open() or self.is_socket_up()
            last_state = self.stats["last_state"]  # snapshot before update
            self.update_stats(running)

            # ✅ Recovery alert logic
            if running:
                if last_state is False:  # just transitioned from down
                    if self.should_alert("redis-recovered"):
                        self.alert_operator("✅ Redis has recovered and is now online.")

                if not accessible:
                    self.alert_operator("⚠️ Redis is active but unreachable via port or socket.")
                self.log("[HAMMER] ✅ Redis is running.")

            else:
                diagnostics = self.collect_redis_diagnostics()
                if self.should_alert("redis-down"):
                    self.alert_operator("❌ Redis is DOWN. Attempting restart.")
                if self.report_role:
                    self.send_data_report(
                        status="DOWN",
                        severity="CRITICAL",
                        details="Redis is not running or unreachable.",
                        metrics=diagnostics
                    )
                self.restart_redis()

        except Exception as e:
            self.log(error=e, block="main_try")

        interruptible_sleep(self, self.interval)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
