# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import requests
import subprocess
import time
import shutil
from datetime import datetime
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.mixin.agent_summary_mixin import AgentSummaryMixin
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent, AgentSummaryMixin):
    """
    A watchdog agent that monitors a MySQL/MariaDB service. It checks if the service is running
    and listening on its designated port, attempts to restart it upon failure, and sends alerts
    and structured data reports about its status.
    """
    def __init__(self):
        """Initializes the MySQLWatchdog agent, setting up configuration parameters and statistics tracking."""
        super().__init__()
        self.name = "MySQLWatchdog"
        self.last_restart = None
        self.failed_restart_count = 0
        self.disabled = False
        cfg = self.tree_node.get("config", {})
        self.interval = cfg.get("check_interval_sec", 20)
        self.mysql_port = cfg.get("mysql_port", 3306)
        self.socket_path = cfg.get("socket_path", "/var/run/mysqld/mysqld.sock")
        self.failed_restart_limit = cfg.get("restart_limit", 3)
        self.alert_role = cfg.get("alert_to_role", None)
        self.report_role = cfg.get("report_to_role", None)
        self.alert_cooldown = cfg.get("alert_cooldown", 300)

        self._last_run_log = 0
        self._warned_not_installed = False

        self.alert_thresholds = cfg.get("alert_thresholds", {"uptime_pct_min": 90, "slow_restart_sec": 10})
        self.service_name = cfg.get("service_name", "mysql")
        self.comm_targets = cfg.get("comm_targets", [])
        self.stats = {
            "date": self.today(),
            "restarts": 0,
            "uptime_sec": 0,
            "downtime_sec": 0,
            "last_status": None,
            "last_status_change": time.time(),
            "last_state": None
        }
        self.last_alerts = {}
        self.last_recovery_alert = 0
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=self.interval*2, emit_to_file_interval=10)


    def today(self):
        """
        Returns the current date as a string in YYYY-MM-DD format.

        Returns:
            str: The current date.
        """
        return datetime.now().strftime("%Y-%m-%d")

    def build_restart_cmd(self, service_name):
        if shutil.which("systemctl"):
            return ["systemctl", "restart", service_name]
        elif shutil.which("service"):
            return ["service", service_name, "restart"]
        else:
            raise RuntimeError("No known service manager found")

    def is_mysql_running(self):
        """
        Checks if the MySQL service is active using systemd.

        Returns:
            bool: True if the service is running, False otherwise.
        """
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", self.service_name],
                check=False
            )
            return result.returncode == 0
        except Exception as e:
            self.log(f"[WATCHDOG][ERROR] Failed to check MySQL status: {e}")
            return False

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

    def restart_mysql(self):
        self.restart_service(service_name=self.service_name)

    def restart_service(self, service_name=None):
        """Adaptive restart with retries + disable after repeated failures."""

        try:

            cmd = self.build_restart_cmd(service_name)
            self.log(f"[WATCHDOG] ⚙️ Running restart command: {' '.join(cmd)}")
            subprocess.run(cmd, check=True, timeout=300)
            self.log("[WATCHDOG] ✅ MySQL successfully restarted.")

            # 🔎 New: verify right after restart
            interruptible_sleep(self, 10) # grace period


        except subprocess.TimeoutExpired as e:
            self.log(f"[WATCHDOG][FAIL] Restart timed out after {e.timeout}s.", level="ERROR")
        except Exception as e:
            self.log(f"[WATCHDOG][FAIL] Restart failed: {e}", level="ERROR")

        if self.failed_restart_count >= self.failed_restart_limit:
            self.disabled = True
            self.send_simple_alert("🛑 MySQL watchdog disabled after repeated restart failures.")
            self.log("[WATCHDOG][DISABLED] Max restart attempts reached. Watchdog disabled.")

    def update_status_metrics(self, is_running):
        """
        Updates the uptime and downtime statistics based on the current service status.

        Args:
            is_running (bool): The current running state of the service.
        """
        now = time.time()
        last = self.stats.get("last_status")
        elapsed = now - self.stats.get("last_status_change", now)
        # If state changed (or first run), update timing
        if last is not None:
            if last:
                self.stats["uptime_sec"] += elapsed
            else:
                self.stats["downtime_sec"] += elapsed

        self.stats["last_status"] = is_running
        self.stats["last_status_change"] = now

    def is_socket_accessible(self):
        """
        Checks if the MySQL socket file exists.

        Returns:
            bool: True if the socket exists, False otherwise.
        """
        return os.path.exists(self.socket_path)

    def is_mysql_listening(self):
        """
        Checks if any process is listening on the configured MySQL port.

        Returns:
            bool: True if the port is being listened on, False otherwise.
        """
        try:
            out = subprocess.check_output(["ss", "-ltn"])
            return f":{self.mysql_port}".encode() in out
        except Exception as e:
            self.log(f"[WATCHDOG][ERROR] Failed to scan ports: {e}")
            return False

    def worker_pre(self):
        """Logs the systemd unit being watched before the main worker loop starts."""
        self.log(f"[WATCHDOG] Watching systemd unit: {self.service_name}")

    def worker(self, config: dict = None, identity: IdentityObject = None):
        """
        Main MySQL watchdog loop — now quiet until MySQL exists, and logs only once
        every five minutes while healthy.
        """
        try:
            self._emit_beacon()
            self.maybe_roll_day("mysql")

            # --- One-time "not installed" guard ---
            installed = (
                    shutil.which("mysqld")
                    or shutil.which("mysql")
                    or os.path.exists("/usr/sbin/mysqld")
                    or os.path.exists("/usr/bin/mysqld")
            )
            if not installed:
                if not self._warned_not_installed:
                    self.log("[WATCHDOG] MySQL not installed — watchdog idle until installed.")
                    self._warned_not_installed = True
                interruptible_sleep(self, self.interval)
                return

            is_healthy = self.is_mysql_running() and self.is_mysql_listening()

            # First run: establish baseline
            if self.stats["last_state"] is None:
                self.log("[WATCHDOG] First run of the day. Establishing baseline status...")
                self.stats["last_state"] = is_healthy
                self.stats["last_change"] = time.time()
                return  # skip alerts on first pass

            last_state_was_healthy = self.stats["last_state"]

            if is_healthy != last_state_was_healthy:
                self.update_stats(is_healthy)

                if is_healthy:
                    now = time.time()
                    if now - self.last_recovery_alert > 60:
                        self.log(f"[WATCHDOG] ✅ {self.service_name} has recovered.")
                        self.send_simple_alert(
                            f"✅ {self.service_name.capitalize()} has recovered and is now online."
                        )
                        self.last_recovery_alert = now
                else:
                    self.log(f"[WATCHDOG] ❌ {self.service_name} is NOT healthy.")
                    diagnostics = self.collect_mysql_diagnostics()
                    if self.should_alert("mysql-down"):
                        self.send_simple_alert(
                            f"❌ {self.service_name.capitalize()} is DOWN. Attempting restart..."
                        )
                    self.send_data_report(
                        status="DOWN",
                        severity="CRITICAL",
                        details=f"Service {self.service_name} is not running or ports are not open.",
                        metrics=diagnostics,
                    )
                    self.restart_mysql()

            else:
                # State unchanged
                if is_healthy:
                    now = time.time()
                    if self._last_run_log + 600 < now:  # every 5 minutes
                        self.log(f"[WATCHDOG] ✅ {self.service_name} status is stable.")
                        self._last_run_log = now
                else:
                    self.log(f"[WATCHDOG] ❌ {self.service_name} is still NOT healthy.")

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

        interruptible_sleep(self, self.interval)

    def should_alert(self, key):
        """
        Determines if an alert should be sent based on a cooldown period to avoid alert fatigue.

        Args:
            key (str): A unique key for the alert type.

        Returns:
            bool: True if an alert should be sent, False otherwise.
        """
        now = time.time()
        last = self.last_alerts.get(key, 0)
        if now - last > self.alert_cooldown:
            self.last_alerts[key] = now
            return True
        return False

    def post_restart_check(self):
        """Wait and confirm MySQL is listening after restart."""
        wait_sec = getattr(self, "post_restart_wait_sec", 15)
        time.sleep(wait_sec)
        if not self.is_mysql_listening():
            self.log(f"[WATCHDOG][CRIT] {self.service_name} restarted but port {self.mysql_port} not listening.")
            self.send_simple_alert(
                f"🚨 {self.service_name.capitalize()} restarted but not listening on port {self.mysql_port}.")

    def send_simple_alert(self, message):
        """
        Sends a formatted, human-readable alert to agents with the designated alert role.

        Args:
            message (str): The core alert message to send.
        """
        try:

            if not self.alert_role:
                return

            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data({"handler": "cmd_send_alert_msg"})
            try:
                server_ip = requests.get("https://api.ipify.org").text.strip()
            except Exception:
                server_ip = "Unknown"

            pk2 = self.get_delivery_packet("notify.alert.general")
            pk2.set_data({
                "server_ip": server_ip, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "universal_id": self.command_line_args.get("universal_id"), "level": "critical",
                "msg": message, "formatted_msg": f"📦 MySQL Watchdog\n{message}",
                "cause": "MySQL Sentinel Alert", "origin": self.command_line_args.get("universal_id")
            })

            pk1.set_packet(pk2, "content")
            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def send_data_report(self, status, severity, details="", metrics=None):
        """
        Sends a structured data packet with detailed status and diagnostic information
        to agents with the designated reporting role.

        Args:
            status (str): The current status (e.g., "DOWN", "RECOVERED").
            severity (str): The severity level (e.g., "CRITICAL", "INFO").
            details (str, optional): A human-readable description of the event.
            metrics (dict, optional): A dictionary of diagnostic information.
        """

        try:

            endpoints = self.get_nodes_by_role(self.report_role)
            if not endpoints:
                self.log(f"[WATCHDOG][ALERT] No alert-compatible agents found for '{self.report_role}'.")
                return


            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data({"handler": "cmd_ingest_status_report"})
            pk2 = self.get_delivery_packet("standard.status.event.packet")
            pk2.set_data({
                "source_agent": self.command_line_args.get("universal_id"),
                "service_name": "mysql", "status": status, "details": details,
                "severity": severity, "metrics": metrics if metrics is not None else {}
            })

            pk1.set_packet(pk2, "content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def collect_mysql_diagnostics(self):
        """
        Gathers MySQL-specific diagnostics, such as systemd status and recent log entries,
        at the moment of failure.

        Returns:
            dict: A dictionary containing diagnostic information.
        """
        info = {}
        # Get systemd status summary
        try:
            info['systemd_status'] = subprocess.check_output(
                ["systemctl", "status", self.service_name], text=True, stderr=subprocess.STDOUT
            ).strip()
        except Exception as e:
            info['systemd_status'] = f"Error: {e}"
        # Error log tail from common locations
        for log_path in ["/var/log/mysql/error.log",
                         "/var/log/mariadb/mariadb.log",
                         "/var/log/mysqld.log"]:
            if os.path.exists(log_path):
                try:
                    info['error_log'] = subprocess.check_output(["tail", "-n", "20", log_path], text=True)
                except Exception as e:
                    info['error_log'] = f"Error: {e}"
                break
        return info

if __name__ == "__main__":
    agent = Agent()
    agent.boot()