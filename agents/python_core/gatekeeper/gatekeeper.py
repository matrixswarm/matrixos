# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Docstrings by Gemini
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import json
import time
import subprocess
import ipaddress
from datetime import datetime
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
import geoip2.database
import requests
import threading
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        self.name = "Gatekeeper"
        cfg = self.tree_node.get("config", {})

        if os.path.exists("/var/log/secure"):
            self.log_path = "/var/log/secure"
        elif os.path.exists("/var/log/auth.log"):
            self.log_path = "/var/log/auth.log"
        else:
            self.log_path = cfg.get("log_path", "/var/log/secure") # Debian/Ubuntu — change to /var/log/secure on RHEL/CentOS

        self.maxmind_db = cfg.get("maxmind_db", "GeoLite2-City.mmdb")
        self.geoip_enabled = cfg.get("geoip_enabled", 1)
        self.always_alert = bool(cfg.get("always_alert", 1))
        self.cooldown_sec = 300
        self.interval=10
        self.last_alerts = {}
        self.tail_thread = None
        cfg_db = str(cfg.get("maxmind_db", "")).strip()

        # If it's an absolute path or a path relative to install_path
        if cfg_db and os.path.isfile(cfg_db):
            self.mmdb_path = cfg_db
        else:
            self.mmdb_path = os.path.join(self.path_resolution["install_path"], "maxmind", "GeoLite2-City.mmdb")

        self.log_dir = os.path.join(self.path_resolution["static_comm_path_resolved"], "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)
        self._emit_beacon_tail_log = self.check_for_thread_poke("tail_log", timeout=60, emit_to_file_interval=10)
        # Report target for structured status events (forensic intake)
        self.alert_role = cfg.get("alert_to_role", None)  # Optional
        self.report_role = cfg.get("report_to_role", None)  # Optional

    def should_alert(self, key):

        if self.always_alert:
            return True

        now = time.time()
        last = self.last_alerts.get(key, 0)
        if now - last > self.cooldown_sec:
            self.last_alerts[key] = now
            return True
        return False

    def resolve_ip(self, ip):
        if not os.path.exists(self.mmdb_path):
            self.log(f"[GATEKEEPER][GEOIP] DB not found at {self.mmdb_path}")
            return {"ip": ip, "city": None, "region": None, "country": None}

        try:
            reader = geoip2.database.Reader(self.mmdb_path)
            response = reader.city(ip)
            return {
                "ip": ip,
                "city": response.city.name,
                "region": response.subdivisions[0].name if response.subdivisions else None,
                "country": response.country.name
            }
        except Exception as e:
            self.log(f"[GATEKEEPER][GEOIP][ERROR] {e}")
            return {"ip": ip}


    def drop_alert(self, info):


        try:

            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                self.log(f"[WATCHDOG][ALERT] No alert-compatible agents found for 'self.alert_role'.")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk2 = self.get_delivery_packet("notify.alert.general")

            try:
                server_ip = requests.get("https://api.ipify.org").text.strip()
            except Exception:
                server_ip = "Unknown"

            # Force inject message
            msg_text = (
                f"🛡️ SSH Login Detected\n\n"
                f"• Server IP: {server_ip}\n"
                f"• User: {info.get('user')}\n"
                f"• IP: {info.get('ip')}\n"
                f"• Location: {info.get('city')}, {info.get('country')}\n"
                f"• Time: {info.get('timestamp')}\n"
                f"• Auth: {info.get('auth_method')}\n"
                f"• Terminal: {info.get('tty')}"
            )

            pk2.set_data({
                "msg": msg_text,
                "universal_id": self.command_line_args.get("universal_id", "unknown"),
                "level": "critical",
                "cause": "SSH Login Detected",
                "origin": self.command_line_args.get("universal_id", "unknown")
            })

            self.log_proto(
                f"ALERT dispatched for user {info.get('user')} from {info.get('ip')}",
                level="WARN",
                block="DROP_ALERT"
            )

            pk1.set_packet(pk2, "content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

            # Also send structured status event for forensic ingestion
            details = {
                'user': info.get('user'),
                'ip': info.get('ip'),
                'location': f"{info.get('city')}, {info.get('country')}",
                'auth_method': info.get('auth_method'),
                'tty': info.get('tty'),
                'timestamp': info.get('timestamp')
            }
            metrics = {'geo': info}
            self.send_status_report('ssh_login_success', 'CRITICAL', details, metrics)

        except Exception as e:
            self.log(error=e, level="ERROR", block="main_try")


    def tail_log(self):
        self.log(f"[GATEKEEPER] Tailing: {self.log_path}")
        self._emit_beacon_tail_log()
        try:
            with subprocess.Popen(
                    ["tail", "-n", "0", "-F", self.log_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
            ) as proc:
                if proc.stdout is None:
                    self.log("[GATEKEEPER] ❌ tail stdout unavailable, aborting.")
                    return

                last_emit = time.time()

                while True:
                    line = proc.stdout.readline()

                    # heartbeat even if no new line
                    now = time.time()
                    if now - last_emit >= 30:  # configurable
                        self._emit_beacon_tail_log()
                        last_emit = now

                    if not line:
                        # tail ended or rotated, break to restart
                        if proc.poll() is not None:
                            self.log("[GATEKEEPER] tail process exited, restarting…")
                            break
                        continue

                    # normal log parsing continues here
                    self._emit_beacon_tail_log()
                    last_emit = now
                    self._process_login_line(line)

        except Exception as e:
            self.log("[GATEKEEPER][ERROR] tail_log exception", error=e)

    def _process_login_line(self, line: str):
        line = line.strip()
        if not line:
            return

        try:
            # ✅ Successful logins
            if "Accepted" in line and "from" in line:
                timestamp = " ".join(line.split()[0:3])

                if "password" in line:
                    auth_method = "password"
                elif "publickey" in line:
                    auth_method = "public key"
                else:
                    auth_method = "unknown"

                user = line.split("for")[1].split("from")[0].strip()
                ip = line.split("from")[1].split()[0].strip()

                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    self.log(f"[GATEKEEPER][SKIP] Invalid IP: {ip}")
                    return

                tty = "unknown"
                geo = self.resolve_ip(ip)
                alert_data = {
                    "event": "ssh_login_success",
                    "user": user,
                    "ip": ip,
                    "tty": tty,
                    "auth_method": auth_method,
                    "timestamp": timestamp,
                    **geo
                }

                self.drop_alert(alert_data)
                self.persist(alert_data)

            # ⚠️ Failed logins (optional, disabled by default)
            elif self.tree_node.get("alert_failures", False) and "Failed password" in line and "from" in line:
                timestamp = " ".join(line.split()[0:3])
                user = line.split("for")[1].split("from")[0].strip()
                ip = line.split("from")[1].split()[0].strip()

                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    self.log(f"[GATEKEEPER][SKIP] Invalid IP: {ip}")
                    return

                geo = self.resolve_ip(ip)
                alert_data = {
                    "event": "ssh_login_failed",
                    "user": user,
                    "ip": ip,
                    "auth_method": "password",
                    "timestamp": timestamp,
                    **geo
                }

                self.drop_alert(alert_data)
                self.persist(alert_data)

        except Exception as e:
            self.log(f"[GATEKEEPER][PARSER][ERROR] Failed to parse login line: {e}")

    def persist(self, data):
        fname = f"ssh_{self.today()}.log"
        path = os.path.join(self.log_dir, fname)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")


    def send_status_report(self, status, severity, details, metrics=None):
        #Send a structured status event packet to the configured role for forensic ingestion.
        try:
            if not self.report_role:
                self.log("[GATEKEEPER] No report_to_role configured, skipping status report.", level='WARN')
                return

            endpoints = self.get_nodes_by_role(self.report_role)
            if not endpoints:
                self.log(f"[GATEKEEPER] No endpoints found for role '{self.report_role}'", level='WARN')
                return

            pk_inner = self.get_delivery_packet("standard.status.event.packet")
            pk_inner.set_data({
                "source_agent": self.command_line_args.get("universal_id", "gatekeeper"),
                "service_name": "system.ssh",
                "status": status,
                "details": details,
                "severity": severity,
                "metrics": metrics or {}
            })

            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({"handler": "cmd_ingest_status_report"})
            pk.set_packet(pk_inner, "content")

            for ep in endpoints:
                pk.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk, ep.get_universal_id())

            self.log(f"[GATEKEEPER] Structured status report sent to role '{self.report_role}'", level='INFO')

        except Exception as e:
            self.log(f"[GATEKEEPER][ERROR] send_status_report failed: {e}", level='ERROR')

    def today(self):
        return datetime.now().strftime("%Y-%m-%d")

    def worker(self, config: dict = None, identity: IdentityObject = None):

        self._emit_beacon()

        if not self.tail_thread or not self.tail_thread.is_alive():
            self.log("[GATEKEEPER] Starting tail_log thread…")
            self.tail_thread = threading.Thread(
                target=self.tail_log,
                name="gatekeeper_tail_log",
                daemon=True
            )
            self.tail_thread.start()

        interruptible_sleep(self, self.interval)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()