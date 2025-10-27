# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import shutil
import threading
import subprocess
import time
import requests
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from datetime import datetime
from core.python_core.mixin.agent_summary_mixin import AgentSummaryMixin
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent, AgentSummaryMixin):
    def __init__(self):
        super().__init__()
        try:
            self.name = "ApacheSentinel"
            cfg = self.tree_node.get("config", {})
            self.interval = cfg.get("check_interval_sec", 10)
            self.service_name = cfg.get("service_name", "httpd")  # or "httpd" on RHEL
            self.ports = cfg.get("ports", [80, 443])
            # New configuration to read both roles
            self.alert_role = cfg.get("alert_to_role", None) #Optional
            self.report_role = cfg.get("report_to_role", None)  # Optional
            self.restart_limit = cfg.get("restart_limit", 3)
            self.mod_status_url = cfg.get("mod_status_url", None)
            self.failed_restarts = 0
            self.disabled = False
            self.alerts = {}
            self.always_alert = bool(cfg.get("always_alert", 1))
            self.alert_cooldown = cfg.get("alert_cooldown", 300)
            self.last_status = None
            self.stats = {
                "date": self.today(),
                "uptime_sec": 0,
                "downtime_sec": 0,
                "restarts": 0,
                "last_state": None,
                "last_change": time.time()
            }

            self._last_run_log = 0
            self._warned_not_installed = False

            self._emit_beacon = self.check_for_thread_poke("worker", timeout=90, emit_to_file_interval=10)

        except Exception as e:
            self.log(f"[__INIT__]", error=e, block="main_try", level="CRITICAL")

    def today(self):
        return datetime.now().strftime("%Y-%m-%d")

    def is_apache_running(self):
        try:
            result = subprocess.run(["systemctl", "is-active", "--quiet", self.service_name], check=False)
            return result.returncode == 0
        except Exception as e:
            self.log(f"[WATCHDOG][ERROR] systemctl failed: {e}")
            return False

    def are_ports_open(self):
        try:
            out = subprocess.check_output(["ss", "-ltn"])
            for port in self.ports:
                if f":{port}".encode() not in out:
                    return False
            return True
        except Exception:
            return False

    def build_restart_cmd(self, service_name):
        if shutil.which("systemctl"):
            return ["systemctl", "restart", service_name]
        elif shutil.which("service"):
            return ["service", service_name, "restart"]
        else:
            raise RuntimeError("No known service manager found")

    def restart_service(self, service_name=None):
        """
        Restart a service in a background thread with timeout protection.
        Works across watchdog agents.
        """
        if self.disabled:
            self.log("[WATCHDOG] Watchdog disabled. Restart skipped.")
            return

        # Default command (Apache on your box is `service httpd start`)
        cmd = self.build_restart_cmd(service_name)

        def _do_restart():
            try:
                for attempt in range(self.restart_limit):
                    try:
                        self._emit_beacon()
                        self.log(f"[WATCHDOG] ⚙️ Running restart command: {' '.join(cmd)} (attempt {attempt + 1})")
                        result = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=300, check=True
                        )
                        self._emit_beacon()
                        self.log(f"[WATCHDOG] ✅ {service_name} restarted. stdout: {result.stdout.strip()}")
                        self.failed_restarts = 0
                        self.stats["restarts"] += 1
                        return  # success, bail out
                    except subprocess.TimeoutExpired:
                        self.failed_restarts += 1
                        self.log(f"[WATCHDOG][FAIL] Restart attempt {attempt + 1} timed out after 300s.", level="ERROR")
                    except subprocess.CalledProcessError as e:
                        self.failed_restarts += 1
                        self.log(f"[WATCHDOG][FAIL] Restart attempt {attempt + 1} failed: {e.stderr}", level="ERROR")

                # If we’re here, all attempts failed
                self.disabled = True
                self.log(f"[WATCHDOG] 💀 Disabled after {self.restart_limit} failed restarts.", level="CRITICAL")
            except Exception as e:
                self.failed_restarts += 1
                self.log(f"[WATCHDOG][FAIL] Unexpected restart error", error=e, level="ERROR")

        # Launch restart in background so worker/beacon loop never freezes
        threading.Thread(target=_do_restart, daemon=True).start()

    def restart_apache(self):
        self.restart_service(service_name=self.service_name)

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

    def send_simple_alert(self, message=None):

        try:

            if not message:
                message = "🚨 APACHE REFLEX TERMINATION\n\nReflex loop failed (exit_code = -1)"


            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                self.log("[WATCHDOG][ALERT] No alert-compatible agents found for 'hive.alert'.")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")

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
                "formatted_msg": f"📣 Apache Watchdog\n{message}",
                "cause": "Apache Sentinel Alert",
                "origin": self.command_line_args.get("universal_id", "unknown")
            })

            self.log_proto(
                f"ALERT dispatched for user { self.command_line_args.get("universal_id", "unknown")} from {server_ip}",
                level="WARN",
                block="DROP_ALERT"
            )

            pk1.set_packet(pk2,"content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")


    def send_data_report(self, status, severity, details="", metrics=None):
        """Sends a structured data packet for analysis, now with optional metrics."""

        try:
            if not self.report_role:
                return

            endpoints = self.get_nodes_by_role(self.report_role)
            if not endpoints:
                self.log(f"[WATCHDOG][ALERT] No alert-compatible agents found for '{self.report_role}'.")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data({"handler": "cmd_ingest_status_report"})

            pk2 = self.get_delivery_packet("standard.status.event.packet")

            # Include the diagnostic metrics in the packet's data payload.
            pk2.set_data({
                "source_agent": self.command_line_args.get("universal_id"),
                "service_name": "apache",
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

    def collect_apache_diagnostics(self):
        info = {}
        # Child process count
        try:
            ps = subprocess.check_output("ps -C apache2 -o pid=", shell=True).decode().strip().splitlines()
            info['child_count'] = len(ps)
        except Exception as e:
            info['child_count'] = f"Error: {e}"

        # Only check for mod_status if the URL is defined in the config.
        if self.mod_status_url:
            try:
                import requests
                r = requests.get(self.mod_status_url, timeout=2)
                r.raise_for_status()  # Raise an exception for bad status codes
                info['mod_status'] = r.text
            except Exception as e:
                info['mod_status'] = f"Error fetching mod_status: {e}"

        # Error log tail
        for log_path in ["/var/log/apache2/error.log", "/var/log/httpd/error_log"]:
            if os.path.exists(log_path):
                try:
                    out = subprocess.check_output(["tail", "-n", "20", log_path], text=True)
                    info['error_log'] = out
                except Exception as e:
                    info['error_log'] = f"Error: {e}"
                break

        return info

    def worker(self, config: dict = None, identity: IdentityObject = None):
        try:
            self._emit_beacon()
            self.maybe_roll_day("apache")

            # --- One-time "not installed" guard ---
            installed = (
                    shutil.which("apache2")
                    or shutil.which("httpd")
                    or os.path.exists("/usr/sbin/httpd")
                    or os.path.exists("/usr/sbin/apache2")
            )
            if not installed:
                if not self._warned_not_installed:
                    self.log("[WATCHDOG] Apache not installed — watchdog idle until installed.")
                    self._warned_not_installed = True
                interruptible_sleep(self, self.interval)
                return

            is_healthy = self.is_apache_running() and self.are_ports_open()

            if self.stats["last_state"] is None:
                self.log("[WATCHDOG] First run of the day. Establishing baseline status...")
                self.stats["last_state"] = is_healthy
                self.stats["last_change"] = time.time()
                return  # skip alerts on first check

            last_state_was_healthy = self.stats["last_state"]

            if is_healthy != last_state_was_healthy:
                self.update_stats(is_healthy)

                if is_healthy:
                    self.log("[WATCHDOG] ✅ Service has recovered.")
                    if self.alert_role and self.should_alert("apache-recovered"):
                        self.send_simple_alert("✅ Apache has recovered and is now online.")
                    if self.report_role:
                        self.send_data_report("RECOVERED", "INFO", "Service is back online and ports are open.")
                else:
                    self.log("[WATCHDOG] ❌ Apache is NOT healthy.")
                    diagnostics = self.collect_apache_diagnostics()
                    if self.alert_role and self.should_alert("apache-down"):
                        self.send_simple_alert("❌ Apache is DOWN or not binding required ports. Attempting restart...")
                    if self.report_role:
                        self.send_data_report(
                            status="DOWN",
                            severity="CRITICAL",
                            details="Service is not running or ports are not binding.",
                            metrics=diagnostics
                        )
                    self.restart_apache()

            else:
                # State unchanged
                if is_healthy:
                    now = time.time()
                    if self._last_run_log + 600 < now:  # every 5 min
                        self.log("[WATCHDOG] ✅ Apache status is stable.")
                        self._last_run_log = now
                else:
                    self.log("[WATCHDOG] ❌ Apache is still NOT healthy.")

        except Exception as e:
            self.log(error=e, block="main_try")

        interruptible_sleep(self, self.interval)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()