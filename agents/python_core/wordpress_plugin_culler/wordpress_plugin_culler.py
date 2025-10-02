#Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Docstrings by Gemini
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import shutil
import json
import time
import subprocess
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep

class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        try:
            self.name = "wordpress_plugin_culler"
            cfg = self.tree_node.get("config", {})

            self.plugin_dir = cfg.get("plugin_dir", "/var/www/html/wp-content/plugins")
            self.quarantine_dir = cfg.get("quarantine_dir", "/var/quarantine/wp_plugins")
            self.trusted_plugins_path = cfg.get("trusted_plugins_path", "/opt/swarm/culler/trusted_plugins.json")

            self.enforce = bool(cfg.get("enforce", False))
            self.interval = int(cfg.get("interval", 15))

            self.alert_role = cfg.get("alert_to_role", "hive.alert")
            self.report_role = cfg.get("report_to_role", "hive.forensics.data_feed")
            self.restart_php_after_quarantine = bool(cfg.get("restart_php_after_quarantine", False))

            self.failed_quarantines = 0
            self.trusted_plugins = {}
            self._emit_beacon = self.check_for_thread_poke("worker", timeout=90, emit_to_file_interval=10)

            self.last_alerts = {}
            self.alert_cooldown = int(cfg.get("alert_cooldown_sec", 300))

        except Exception as e:
            self.log("[PLUGIN-CULLER][__INIT__]", error=e, block="main_try", level="CRITICAL")

    # === Trusted Hash Handling ===
    def _reload_trusted(self):
        try:
            if os.path.exists(self.trusted_plugins_path):
                with open(self.trusted_plugins_path, "r") as f:
                    self.trusted_plugins = json.load(f)
            else:
                self.trusted_plugins = {}
        except Exception as e:
            self.log("[PLUGIN-CULLER] Failed to load trusted_plugins.json", error=e)

    def _sha256_of_folder(self, folder_path):
        import hashlib
        hash_sha = hashlib.sha256()
        for root, dirs, files in sorted(os.walk(folder_path)):
            for file in sorted(files):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, folder_path).replace("\\", "/")
                try:
                    with open(file_path, "rb") as f:
                        while chunk := f.read(8192):
                            hash_sha.update(rel_path.encode("utf-8"))
                            hash_sha.update(chunk)
                except Exception:
                    continue
        return hash_sha.hexdigest()

    # === Core Scanning Loop ===
    def _scan_plugins(self):
        found = {}
        for folder in os.listdir(self.plugin_dir):
            ppath = os.path.join(self.plugin_dir, folder)
            if not os.path.isdir(ppath):
                continue

            hash_val = self._sha256_of_folder(ppath)
            found[folder] = hash_val

            if folder not in self.trusted_plugins:
                self._handle_untrusted(folder, ppath, hash_val, "not in trust list")
            elif self.trusted_plugins[folder] != hash_val:
                self._handle_untrusted(folder, ppath, hash_val, "hash mismatch")

        # Log trusted plugins missing from disk
        for t_folder in set(self.trusted_plugins) - set(found):
            self.log(f"[PLUGIN-CULLER] Trusted plugin '{t_folder}' missing from disk.")

    def should_alert(self, key):
        now = time.time()
        last = self.last_alerts.get(key, 0)
        if now - last > self.alert_cooldown:
            self.last_alerts[key] = now
            return True
        return False

    def send_data_report(self, status, severity, details="", metrics=None):
        try:
            if not self.report_role:
                return
            endpoints = self.get_nodes_by_role(self.report_role)
            if not endpoints:
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data({"handler": "cmd_ingest_status_report"})

            pk2 = self.get_delivery_packet("standard.status.event.packet")
            pk2.set_data({
                "source_agent": self.command_line_args.get("universal_id"),
                "service_name": "wordpress.plugins",
                "status": status,
                "details": details,
                "severity": severity,
                "metrics": metrics if metrics else {}
            })

            pk1.set_packet(pk2, "content")
            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="send_data_report")

    # === Untrusted Handler ===
    def _handle_untrusted(self, folder, ppath, hash_val, reason):
        info = {
            "plugin": folder,
            "path": ppath,
            "hash": hash_val,
            "reason": reason,
            "enforce": self.enforce,
            "timestamp": int(time.time())
        }

        if self.should_alert(folder):
            self.drop_alert(info)
            self.send_data_report(
                status="UNAUTHORIZED_PLUGIN",
                severity="CRITICAL",
                details=f"{reason}: {folder}",
                metrics=info
            )


        if self.enforce:
            try:
                qpath = os.path.join(self.quarantine_dir, f"{folder}_{int(time.time())}")
                shutil.move(ppath, qpath)
                info["action"] = f"quarantined:{qpath}"
                self.log(f"[PLUGIN-CULLER] Quarantined {folder} → {qpath}")
                self.drop_alert(info)
            except Exception as e:
                self.failed_quarantines += 1
                info["action"] = "quarantine_failed"
                self.log(f"[PLUGIN-CULLER] Failed to quarantine {folder}", error=e)
                self.drop_alert(info)

        if self.restart_php_after_quarantine:
            self._restart_php_fpm()

    # === Alert Dispatch (Gatekeeper style) ===
    def drop_alert(self, info: dict):
        try:
            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                self.log("[PLUGIN-CULLER][ALERT] No alert-compatible agents found.", level="WARN")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk2 = self.get_delivery_packet("notify.alert.general")

            msg_text = (
                f"🧹 WordPress Plugin Culler Alert\n\n"
                f"• Plugin: {info.get('plugin')}\n"
                f"• Path: {info.get('path')}\n"
                f"• Reason: {info.get('reason')}\n"
                f"• Action: {info.get('action','detected')}\n"
                f"• Hash: {info.get('hash')}\n"
                f"• Enforce: {info.get('enforce')}\n"
                f"• Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )

            pk2.set_data({
                "msg": msg_text,
                "universal_id": self.command_line_args.get("universal_id", "unknown"),
                "level": "critical",
                "cause": "Unauthorized WordPress Plugin",
                "origin": self.command_line_args.get("universal_id", "unknown")
            })

            self.log_proto(
                f"ALERT dispatched for plugin {info.get('plugin')} at {info.get('path')}",
                level="WARN",
                block="DROP_ALERT"
            )

            pk1.set_packet(pk2, "content")
            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="drop_alert", level="ERROR")

    # === Service Restarts ===
    def _restart_php_fpm(self):
        try:
            if shutil.which("systemctl"):
                subprocess.run(["systemctl", "restart", "php-fpm"], check=True)
                self.log("[PLUGIN-CULLER] Restarted php-fpm via systemctl")
            elif shutil.which("service"):
                subprocess.run(["service", "php7.4-fpm", "restart"], check=True)
                self.log("[PLUGIN-CULLER] Restarted php7.4-fpm via service")
        except Exception as e:
            self.log(f"[PLUGIN-CULLER] Failed to restart PHP-FPM", error=e)

    # === Main Worker ===
    def worker(self, config: dict = None, identity=None):
        self._emit_beacon()
        self._reload_trusted()
        self._scan_plugins()
        interruptible_sleep(self, self.interval)

    # === Remote Commands ===
    def cmd_reload_trusted_plugins(self, content, packet, identity=None):
        self._reload_trusted()
        self.log("[PLUGIN-CULLER] Trusted plugins reloaded by remote command.")

    def cmd_toggle_enforce(self, content, packet, identity=None):
        enforce_val = content.get("enforce")
        if enforce_val is not None:
            self.enforce = bool(enforce_val)
            self.log(f"[PLUGIN-CULLER] Enforce mode set to {self.enforce}")

    def _generate_trust_file(self, plugin_dir=None, output_path=None):
        import hashlib
        try:
            plugin_dir = plugin_dir or self.plugin_dir
            output_path = output_path or self.trusted_plugins_path

            trust_map = {}
            for folder in os.listdir(plugin_dir):
                full_path = os.path.join(plugin_dir, folder)
                if not os.path.isdir(full_path):
                    continue
                # Hash whole folder
                h = hashlib.sha256()
                for root, dirs, files in os.walk(full_path):
                    for fname in sorted(files):
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, plugin_dir).replace("\\", "/")
                        with open(fpath, "rb") as f:
                            while chunk := f.read(8192):
                                h.update(rel.encode())
                                h.update(chunk)
                trust_map[folder] = h.hexdigest()

            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(trust_map, f, indent=2)

            self.log(f"[PLUGIN-CULLER] ✅ Trust file generated at {output_path}")
            return True
        except Exception as e:
            self.log("[PLUGIN-CULLER] ❌ Failed to generate trust file", error=e)
            return False

    # === RPC Command Handler ===
    def cmd_generate_trust_file(self, content, packet, identity=None):
        plugin_dir = content.get("plugin_dir", self.plugin_dir)
        output_path = content.get("output_path", self.trusted_plugins_path)
        if self._generate_trust_file(plugin_dir, output_path):
            self._reload_trusted()
            self.log("[PLUGIN-CULLER] ✅ Trust file regenerated and reloaded.")


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
