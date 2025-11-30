# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Tripwire v2 – Global File Guard
import sys
import os

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from pathlib import Path
import time
import shutil
import json
from datetime import datetime
import inotify.adapters
import inotify.constants
from core.python_core.class_lib.inotify_events.jedi_event_flow import JediEventFlow
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.class_lib.crypto.symmetric_encryption.aes.aes import AESHandlerBytesShim

class Agent(BootAgent):
    """
    Tripwire v2 – GlobalGuard

    A defensive agent that monitors specified filesystem paths for write events
    (create, modify, move) using the Linux inotify mechanism. It enforces a simple
    security policy based on paths and file extensions to identify suspicious activity.

    Core Features:
      * **Filesystem Monitoring:** Uses `inotify` to asynchronously listen for
          filesystem events on configured `watch_paths`.
      * **Policy Engine:** Determines suspiciousness based on `suspicious_extensions`
          and `allowed_extensions`. Ignored paths are whitelisted.
      * **Enforcement Mode:**
          * `ENFORCE` (Active): Moves suspicious files to a timestamped quarantine
              directory structure under `/matrix/quarantine`.
          * `DRY-RUN` (Simulated): Logs and alerts what *would* have been quarantined.
          * `Detect-Only` (Enforce=False): Logs detections without quarantining.
      * **Alerting:** Dispatches alerts to a configured role (`alert_to_role`)
          upon detection or quarantine, respecting a per-path cooldown period.
      * **Persistence:** Encrypts and saves alert history to an on-disk store.
      * **RPC Interface:** Provides commands for checking status, toggling
          enforcement/dry-run, resetting watch paths, and managing quarantined items.
    """

    def __init__(self):
        super().__init__()
        try:

            # Retrieve inotify kernel limits for watches and instances
            # mw: max_user_watches, mi: max_user_instances
            mw, mi = self._get_kernel_inotify_limits()
            # Log the kernel limits to help debug configuration issues with inotify
            self.log(f"[TRIPWIRE-GUARD] Kernel inotify limits: max_user_watches={mw}, max_user_instances={mi}")

            # Initialize the inotify notifier and related state
            self._notifier = None  # The inotify notifier instance (to be created later)
            self._logged_watch_paths = set()  # Keeps track of paths that are being watched
            self._rebuild_flag = False  # Flag to determine if watchers need rebuilding

            # Load configuration for tripwire from "tree_node" (possibly user-defined settings)
            cfg = self.tree_node.get("config", {}) or {}

            # Get the list of directories to watch and ignore from the configuration
            watch_paths = cfg.get("watch_paths", [])  # Directories to monitor for changes
            self._ignore_paths = cfg.get("ignore_paths", [])  # Directories or paths to ignore

            # Normalize and clean up the paths to make them absolute or consistent format
            self._watch_paths = self._normalize_watch_paths(watch_paths)

            # Quarantine settings (where suspicious files will be moved)
            self._quarantine_root = cfg.get("quarantine_root", "/matrix/quarantine")
            # Ensure the quarantine directory exists (create it if necessary)
            os.makedirs(self._quarantine_root, exist_ok=True)

            # Operation mode settings
            self._dry_run = bool(cfg.get("dry_run", False))  # If True, no real enforcement is done
            self._enforce = bool(cfg.get("enforce", True))  # If True, security rules are enforced

            # Configure file extension policies
            self.allowed_extensions = set(cfg.get("allowed_extensions", []))  # Safe file extensions
            self.suspicious_extensions = set(cfg.get("suspicious_extensions", []))  # Extensions to flag as suspicious

            # Define alert and RPC (Remote Procedure Call) roles
            self.alert_role = cfg.get("alert_to_role", None)  # Role/handler to alert in case of issues
            self.rpc_role = cfg.get("rpc_router_role", "hive.rpc")  # Default role for RPC communication

            # Cooldown period to prevent triggering too many alerts/logs for the same path
            self._cooldown = int(cfg.get("cooldown", 300))  # Default: 300 seconds

            # Scan interval (defines how often the inotify `event_gen` loop runs)
            self._interval = int(cfg.get("interval", 5))  # Default: 5 seconds

            # Timeout for inotify event generation (defines maximum wait time for events)
            self._inotify_timeout = int(cfg.get("inotify_timeout", 60))  # Default: 60 seconds

            # Initialize the Jedi event flow handler (handles event processing and post-processing logic)
            self._jedi = JediEventFlow(logger=self.log)  # Custom logic encapsulated in this object

            # Avoid spamming alerts and quarantining the same issue multiple times
            self._last_alert = 0  # Timestamp of the last sent alert
            self._last_quarantine = {}  # Stores the last quarantined files to avoid duplicate quarantines

            # Silent mode flag (if True, suppress specific outputs or logs)
            self._silent_mode = False

            # Restore whitelist (tracks files or paths that are explicitly allowed)
            self._restore_whitelist = {}

            # Path to the persistent store for alerts
            self._alert_store_path = os.path.join(self.path_resolution["static_comm_path_resolved"],
                                                  "tripwire_alerts.json")

            # Heartbeat beacon for the worker and the tripwire guard
            # These beacons ensure the system is healthy and operating correctly, emitting updates at specific intervals
            self._emit_beacon = self.check_for_thread_poke(
                "worker",
                timeout=self._interval * 12,  # Set worker beacon timeout based on interval
                emit_to_file_interval=10  # Emit every 10 seconds to log or file
            )

            self._emit_beacon_trip_guard = self.check_for_thread_poke(
                "tripwire_guard",
                timeout=self._inotify_timeout * 2,  # Tripwire guard timeout based on inotify timeout
                emit_to_file_interval=10
            )

            # Log the initialization state for debugging purposes
            self.log(
                f"[TRIPWIRE-GUARD][INIT] watch={self._watch_paths} ignore={self._ignore_paths} "
                f"dry_run={self._dry_run} enforce={self._enforce}"
            )

            # Security configuration (symmetric encryption)
            # This is used to securely handle sensitive data (e.g., files in quarantine)
            self._aes_key = cfg.get('security').get('symmetric_encryption').get('key')  # AES key for encryption
            self._aes = AESHandlerBytesShim(self._aes_key)  # Initialize AES encryption handler

        except Exception as e:
            self.log("[TRIPWIRE-GUARD][INIT] Failed to init", error=e, level="CRITICAL")

    # ---------- Core Helpers ----------
    def _is_ignored(self, full_path: str) -> bool:
        """Check if the given path should be ignored based on the ignore list."""
        full_path = os.path.abspath(full_path)
        for p in self._ignore_paths:
            if full_path.startswith(p + os.sep) or full_path == p:
                return True
        return False

    def _get_ext(self, full_path: str) -> str:
        """Extract and return the file extension from the given file name."""
        _, ext = os.path.splitext(full_path)
        return ext.lower()

    def _is_suspicious(self, full_path: str, event_types) -> bool:
        """
        Simple first-pass policy:
          • If path is ignored → not suspicious
          • If extension in suspicious_extensions → suspicious
          • If extension not in allowed_extensions and not empty → suspicious
          • DELETE events are just logged, not quarantined

        """
        if self._is_ignored(full_path):
            return False

        ext = self._get_ext(full_path)

        # Delete events aren't quarantine candidates; just interesting
        if "IN_DELETE" in event_types or "IN_DELETE_SELF" in event_types:
            return False

        # Strong rule: obviously bad extensions
        if ext in self.suspicious_extensions:
            return True

        # If we have a known allowed set, treat unknowns as suspicious
        if self.allowed_extensions and ext not in self.allowed_extensions and ext != "":
            return True

        return False

    def _save_alerts(self, data: dict):
        """Save the current alerts to disk for persistent storage."""
        try:
            raw = json.dumps(data, indent=2).encode()
            ct = self._aes.encrypt(raw)
            tmp = self._alert_store_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._alert_store_path)
        except Exception as e:
            self.log(error=e, level="CRITICAL", block="main_try")

    def _load_alerts(self):
        """
        Load and decrypt the Tripwire alert store.
        If decryption fails (due to corruption, wrong key, or tampering),
        automatically quarantine the bad file and reset to a clean list.
        """
        try:
            if not os.path.exists(self._alert_store_path):
                return []

            ct = Path(self._alert_store_path).read_bytes()

            try:
                pt = self._aes.decrypt(ct)
                data = json.loads(pt.decode())
                if not isinstance(data, list):
                    raise ValueError("Decrypted payload is not a list.")
                return data

            except Exception as e:
                # --- Self-Destruct Protocol ---
                bad_path = f"{self._alert_store_path}.corrupt_{int(time.time())}"
                try:
                    Path(self._alert_store_path).rename(bad_path)
                    self.log(f"[ALERT-STORE] ⚠️ Decryption failed, quarantined corrupt file → {bad_path}")
                except Exception as re:
                    self.log(f"[ALERT-STORE] ❌ Failed to rename corrupt file: {re}")
                self._save_alerts([])  # recreate clean empty encrypted store
                self.log(f"[ALERT-STORE] 🔄 Reset Tripwire alert store (fresh). Reason: {e}")
                return []

        except Exception as e:
            self.log(error=e, level="CRITICAL", block="_load_alerts")
            return []

    def _cooldown_ok(self) -> bool:
        """Check if enough time has passed since the last alert for the given path."""
        now = time.time()
        if now - self._last_alert < self._cooldown:
            return False
        self._last_alert = now
        return True

    def _get_kernel_inotify_limits(self):
        """Fetch the kernel's inotify limits for max watches and instances."""
        try:
            with open("/proc/sys/fs/inotify/max_user_watches") as f:
                max_watches = int(f.read().strip())
            with open("/proc/sys/fs/inotify/max_user_instances") as f:
                max_instances = int(f.read().strip())
            return max_watches, max_instances
        except Exception as e:
            self.log(f"[TRIPWIRE-GUARD][ERROR] Cannot read kernel inotify limits: {e}")
            return 8192, 128  # safe fallback

    def _get_current_watchers(self):
        """Retrieve the current number of inotify watchers in use."""
        try:
            pid = os.getpid()
            count = 0
            for fd in os.listdir(f"/proc/{pid}/fdinfo"):
                try:
                    with open(f"/proc/{pid}/fdinfo/{fd}") as f:
                        if "inotify" in f.read():
                            count += 1
                except:
                    pass
            return count
        except:
            return 0

    def _estimate_watchers_needed(self):
        """Estimate the total number of inotify watches needed for the given directories."""
        try:
            dirs = 0
            for entry in self._watch_paths:
                base = entry.get("path")
                if not base:
                    continue
                for root, _, _ in os.walk(base):
                    if self._is_ignored(root):
                        continue
                    dirs += 1
            return dirs

        except Exception as e:
            self.log(error=e, level="CRITICAL", block="main_try")

    def cmd_tripwire_reset(self, content, packet, identity):
        """Reset the inotify tripwire instance to reinitialize watchers."""
        try:
            self.log("[TRIPWIRE] RPC received — resetting watch paths.")
            new_paths = content.get("paths")
            if new_paths:
                self._watch_paths = self._normalize_watch_paths(new_paths)
            self._rebuild_flag = True
        except Exception as e:
            self.log(error=e, level="CRITICAL", block="main_try")

    def _build_quarantine_path(self, full_path: str) -> str:
        """
        /opt/quarantine/global/<timestamp>/<full/absolute/path>
        e.g. /opt/quarantine/global/20251127T083000Z/sites/public_html/.../file.php
        """
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        # Strip leading "/" so it becomes a proper relative path under ts dir
        rel = full_path.lstrip(os.sep)
        return os.path.join(self._quarantine_root, ts, rel)


    # ============================================================
    # RPC COMMAND: LIST STATUS
    # ============================================================
    def cmd_list_status(self, content, packet, identity):
        """
        Return current Tripwire runtime status, including inotify kernel limits,
        watcher counts, and estimates of total filesystem entries.
        """
        try:
            max_watches, max_instances = self._get_kernel_inotify_limits()
            current_watchers = self._get_current_watchers()
            estimated_needed = self._estimate_watchers_needed()

            status = {
                "enforce": self._enforce,
                "dry_run": self._dry_run,
                "ignore": self._ignore_paths,
                "paths": self._watch_paths,
                "cooldown": self._cooldown,
                "suspicious_ext": list(self.suspicious_extensions),
                "allowed_ext": list(self.allowed_extensions),
                "timestamp": int(time.time()),

                # new intel
                "kernel_limits": {
                    "max_user_watches": max_watches,
                    "max_user_instances": max_instances,
                },
                "watcher_usage": {
                    "current_watches": current_watchers,
                    "estimated_needed": estimated_needed,
                    "utilization_percent": round((current_watchers / max_watches) * 100, 2)
                    if max_watches else 0,
                },
            }

            self.crypto_reply(
                response_handler=content.get("return_handler", "tripwire.status"),
                payload=status,
                session_id=content.get("session_id"),
                token=content.get("token")
            )

        except Exception as e:
            self.log("[STATUS][ERROR] Failed to compile status", error=e)

    # ============================================================
    # RPC COMMAND: TOGGLE ENFORCE
    # ============================================================
    def cmd_toggle_enforce(self, content, packet, identity):
        """
        Toggle enforcement mode (true/false) and return the new value.
        """
        # Flip actual enforce flag
        self._enforce = not self._enforce

        # Respond back to Phoenix
        self.crypto_reply(
            response_handler=content.get("return_handler", "tripwire.enforce"),
            payload={"enforce": self._enforce},
            session_id=content.get("session_id"),
            token=content.get("token")
        )

    def cmd_change_limits(self, content, packet, identity):
        """Change kernel inotify watch limits on the fly (root-only)."""
        new_watch_limit = int(content.get("max_user_watches", 524288))
        new_instance_limit = int(content.get("max_user_instances", 256))
        try:
            os.system(f"sysctl -w fs.inotify.max_user_watches={new_watch_limit}")
            os.system(f"sysctl -w fs.inotify.max_user_instances={new_instance_limit}")
            self.log(f"[TRIPWIRE] Updated inotify limits: watches={new_watch_limit}, instances={new_instance_limit}")
        except Exception as e:
            self.log("[TRIPWIRE][CHANGE-LIMITS][ERROR]", error=e)

    def cmd_restore_quarantine_item(self, content, packet, identity):
        """Restore a specific quarantined item back to its original location."""
        orig = content["original_path"]
        qpath = content["qpath"]

        # silence & disable enforce
        prev_enforce = self._enforce
        self._enforce = False
        self._silent_mode = True
        self._restore_whitelist[orig] = time.time()

        try:
            shutil.move(qpath, orig)
        except Exception as e:
            self.log(f"[RESTORE][ERROR] {e}")
        finally:
            self._silent_mode = False
            self._enforce = prev_enforce

    # ============================================================
    # RPC COMMAND: TOGGLE DRY-RUN
    # ============================================================
    def cmd_toggle_dry_run(self, content, packet, identity:IdentityObject=None):
        """Toggle the 'dry run' mode for monitoring without enforcement."""
        self._dry_run = not self._dry_run
        self.crypto_reply(
            response_handler=content.get("return_handler", "tripwire.dryrun"),
            payload={"dry_run": self._dry_run},
            session_id=content.get("session_id"),
            token=content.get("token")
        )

    def _ensure_dir(self, path: str):
        """Ensure that the given directory path exists, creating it if necessary."""
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            self.log(f"[TRIPWIRE-GUARD][ERROR] mkdir failed for {path}", error=e, level="ERROR")

    def cmd_list_alerts(self, content, packet, identity):
        """List all previously generated alerts."""
        alerts = self._load_alerts()
        self.crypto_reply(
            response_handler=content.get("return_handler", "tripwire.alerts"),
            payload={"alerts": alerts},
            session_id=content.get("session_id"),
            token=content.get("token")
        )

    def cmd_restore_item(self, content, packet, identity:IdentityObject=None):
        """Restore an item from an abnormal state to its safe state."""
        orig = content["original_path"]
        qpath = content["qpath"]

        prev_enforce = self._enforce
        self._silent_mode = True
        self._enforce = False
        self._restore_whitelist[orig] = time.time()

        try:
            os.makedirs(os.path.dirname(orig), exist_ok=True)
            shutil.move(qpath, orig)
            result = True
        except Exception as e:
            self.log("[RESTORE][ERROR]", error=e)
            result = False
        finally:
            self._silent_mode = False
            self._enforce = prev_enforce

        # Update alert entry
        alerts = self._load_alerts()
        for a in alerts:
            if a.get("quarantine_path") == qpath:
                a["status"] = "restored"

        self._save_alerts(alerts)

        self.crypto_reply(
            response_handler=content.get("return_handler", "tripwire.restore_ack"),
            payload={"success": result},
            session_id=content.get("session_id"),
            token=content.get("token")
        )

    def cmd_restore_all(self, content, packet, identity):
        """Restore all quarantined items to their original state."""
        alerts = self._load_alerts()
        restored = []

        prev = self._enforce
        self._silent_mode = True
        self._enforce = False

        try:
            for a in alerts:
                if a.get("status") != "quarantined":
                    continue

                orig = a["path"]
                qpath = a["quarantine_path"]
                self._restore_whitelist[orig] = time.time()

                try:
                    os.makedirs(os.path.dirname(orig), exist_ok=True)
                    shutil.move(qpath, orig)
                    a["status"] = "restored"
                    restored.append(orig)
                except Exception as e:
                    self.log("[RESTORE-ALL][ERROR]", error=e)

            # Save updated alerts
            self._save_alerts(alerts)

        finally:
            self._silent_mode = False
            self._enforce = prev

        self.crypto_reply(
            response_handler=content.get("return_handler", "tripwire.restore_all_ack"),
            payload={"restored": restored},
            session_id=content.get("session_id"),
            token=content.get("token")
        )

    def cmd_delete_alert(self, content, packet, identity):
        """Delete a specified alert from the alert store."""
        alert_id = content.get("alert_id")
        if not alert_id:
            return

        alerts = self._load_alerts()
        new_alerts = [a for a in alerts if a.get("id") != alert_id]

        try:
            self._save_alerts(new_alerts)
            ok = True
        except:
            ok = False

        self.crypto_reply(
            response_handler=content.get("return_handler", "tripwire.delete_ack"),
            payload={"success": ok, "alert_id": alert_id},
            session_id=content.get("session_id"),
            token=content.get("token")
        )

    # ---------- Alert Dispatch ----------
    def drop_alert(self, info: dict):
        """
        Dispatch a general alert to whatever agent handles Discord/Phoenix alerts,
        using the same pattern as wordpress_plugin_guard.
        """
        try:
            if not self.alert_role:
                self.log("[TRIPWIRE-GUARD][ALERT] No alert_role configured, skipping.", level="WARN")
                return

            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                self.log(f"[TRIPWIRE-GUARD][ALERT] No endpoints found for role={self.alert_role}", level="WARN")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk2 = self.get_delivery_packet("notify.alert.general")

            msg_text = (
                "🛡 Tripwire v2 Alert\n\n"
                f"• Path: {info.get('path')}\n"
                f"• Event: {info.get('event')}\n"
                f"• Action: {info.get('action', 'observed')}\n"
                f"• DryRun: {info.get('dry_run')}\n"
                f"• Enforce: {info.get('enforce')}\n"
                f"• Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}"
            )

            pk2.set_data({
                "msg": msg_text,
                "universal_id": self.command_line_args.get("universal_id", "tripwire_guard"),
                "level": "critical" if info.get("action") in ("quarantine", "would_quarantine") else "info",
                "cause": "Filesystem Drop Detected",
                "origin": self.command_line_args.get("universal_id", "tripwire_guard")
            })

            pk1.set_packet(pk2, "content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

            # Optional: also send a structured status event to Phoenix feed / hive logger
            # (reuse plugin_guard.send_status_report style if you want deeper telemetry)
        except Exception as e:
            self.log("[TRIPWIRE-GUARD][ALERT] Failed to dispatch alert", error=e, level="ERROR")

    # ---------- Core Event Handling ----------
    def _handle_event(self, path: str, filename: str, event_types):
        """Process events triggered by inotify for a specific file or directory."""
        if self._silent_mode:
            return

        # We only care about these events
        if not any(ev in event_types for ev in (
                "IN_CREATE",
                "IN_MODIFY",
                "IN_CLOSE_WRITE",
                "IN_MOVED_TO"
        )):
            return

        full_path = os.path.join(path, filename)

        # Allow a 3-second grace period after restore
        ts = self._restore_whitelist.get(full_path)
        if ts and (time.time() - ts < 3):
            return

        if self._jedi.fallout(full_path):
            self.log(f"[TRIPWIRE][FALLOUT] Ignoring fallout for {full_path}")
            return

        # Must be suspicious
        if not self._is_suspicious(full_path, event_types):
            return

        # Before returning, always log to Jedi engine
        if "IN_CREATE" in event_types:
            self._jedi.record(full_path, "created")

        if "IN_MODIFY" in event_types or "IN_CLOSE_WRITE" in event_types:
            self._jedi.record(full_path, "modified")

        if "IN_MOVED_TO" in event_types or "IN_MOVED_FROM" in event_types:
            self._jedi.record(full_path, "moved")

        # Quarantine target
        qpath = self._build_quarantine_path(os.path.abspath(full_path))

        # Cooldown check (alerts ONLY)
        alert_allowed = self._cooldown_ok()

        # Fallout suppression: prevent spam after a file is already removed
        recent_q = self._last_quarantine.get(full_path, 0)
        if time.time() - recent_q < 1.5:  # 1.5 sec anti-spam window
            return

        # --- INFO payload (shared for alert/quarantine) ---
        info = {
            "path": full_path,
            "event": ",".join(event_types),
            "quarantine_path": qpath,
            "dry_run": self._dry_run,
            "enforce": self._enforce,
        }

        # === DRY-RUN / DETECT-ONLY MODE ===
        if self._dry_run or not self._enforce:

            # Action metadata
            if self._enforce:
                info["action"] = "would_quarantine"
            else:
                info["action"] = "detected"

            # Build the correct log message
            if self._enforce:
                # Dry-run ONLY
                msg = f"Would quarantine {full_path} → {qpath}"
            else:
                # Detect-only mode (not enforcing)
                msg = f"Would quarantine {full_path} → {qpath} (not enforced)"

            self.log(f"[TRIPWIRE-GUARD][DRY-RUN] {msg}", level="WARN")

            # ---- ALERT LOGIC ----
            # Alerts should only fire when NOT in cooldown AND when enforce is true
            if alert_allowed and self._enforce:
                self.drop_alert(info)

            # Cooldown triggered (and enforce == true)
            elif not alert_allowed and self._enforce:
                remaining = int(self._cooldown - (time.time() - self._last_alert))
                self.log(
                    f"[TRIPWIRE-GUARD][COOLDOWN] Suppressed alert for {full_path} "
                    f"(next alert in {remaining}s)",
                    level="INFO"
                )

            return

        # === ENFORCEMENT MODE: quarantine always, no cooldown ===
        try:

            self._ensure_dir(os.path.dirname(qpath))

            if os.path.exists(full_path):

                self._store_alert({
                    "id": os.path.basename(qpath),
                    "ts": int(time.time()),
                    "path": full_path,
                    "quarantine_path": qpath,
                    "status": "quarantined"
                })
                shutil.move(full_path, qpath)
                info["action"] = "quarantine"
                self._last_quarantine[full_path] = time.time()
                self.log(f"[TRIPWIRE-GUARD][QUARANTINE] {full_path} → {qpath}", level="WARN")
            else:
                info["action"] = "missing_on_enforce"
                self.log(f"[TRIPWIRE-GUARD][QUARANTINE] {full_path} vanished before move.", level="WARN")

            # Alert only if cooldown allows
            if alert_allowed:
                self.drop_alert(info)
            else:
                remaining = int(self._cooldown - (time.time() - self._last_alert))
                self.log(f"[TRIPWIRE-GUARD][COOLDOWN] Suppressed alert for {full_path} "
                         f"(next alert in {remaining}s)", level="INFO")

        except Exception as e:
            info["action"] = "quarantine_failed"
            self.log(f"[TRIPWIRE-GUARD][ERROR] Failed to quarantine {full_path} → {qpath}", error=e, level="ERROR")

            if alert_allowed:
                self.drop_alert(info)
            else:
                remaining = int(self._cooldown - (time.time() - self._last_alert))
                self.log(f"[TRIPWIRE-GUARD][COOLDOWN] Suppressed alert for {full_path} "
                         f"(next alert in {remaining}s)", level="INFO")

    def _store_alert(self, alert):
        """Store the given alert in memory or on disk for later processing."""
        try:
            existing = []
            if os.path.exists(self._alert_store_path):
                existing =  self._load_alerts()
            existing.append(alert)
            self._save_alerts(existing)
        except Exception as e:
            self.log("[TRIPWIRE][ALERT-STORE] Failed to save alert", error=e)

    # ---------- Agent Lifecycle ----------
    def post_boot(self):
        """Perform post-initialization tasks after loading configuration."""
        try:
            self.log(f"{self.NAME} – Tripwire v2 GlobalGuard online.")
            self._notifier = inotify.adapters.Inotify()
            self._build_watcher_table()
            threading = __import__("threading")
            threading.Thread(target=self._listen_for_events, daemon=True).start()
        except Exception as e:
            self.log(error=e, level="ERROR", block="main_try")

    def _clear_all_watches(self):
        """Clear all active inotify watches, resetting the watcher state."""
        try:
            if self._notifier:
                self._notifier = inotify.adapters.Inotify()  # recreate the notifier object
            self.watch_count = 0
        except Exception as e:
            self.log(f"[TRIPWIRE] Failed to clear watches: {e}")

    def _listen_for_events(self):
        """Listen for inotify events and handle them in real-time."""
        try:
            self.log("[TRIPWIRE] 🔌 Listening for file events…")
            for event in self._notifier.event_gen():

                self._emit_beacon_trip_guard()
                # flush any events qued to the logs
                self._jedi.flush()

                if event is None:
                    continue  # just in case
                try:
                    (_, type_names, path, filename) = event

                    if not path or not filename:
                        continue

                    if isinstance(path, bytes):
                        path = path.decode(errors="replace")
                    if isinstance(filename, bytes):
                        filename = filename.decode(errors="replace")

                    self._handle_event(path, filename, type_names)
                except Exception as e:
                    self.log(f"[TRIPWIRE][EVT-FAIL] {event} → {e}", level="ERROR")
        except Exception as e:
            self.log("[TRIPWIRE][EVT-LOOP-CRASH] Event listener crashed", error=e)

    def _build_watcher_table(self):
        """Build and maintain a table of active watchers to track monitored paths."""
        try:
            max_watches, max_instances = self._get_kernel_inotify_limits()
            current = self._get_current_watchers()
            needed = self._estimate_watchers_needed()

            if current + needed > int(max_watches * 0.8):
                self.log("[TRIPWIRE-GUARD][CRITICAL] Watcher limit too low! Sentinel refusing to start.")
                self.drop_alert({
                    "path": "SENTINEL",
                    "event": "RESOURCE_LIMIT",
                    "action": "fail_safe",
                    "message": (
                        f"Tripwire would exceed kernel max_user_watches.\n"
                        f"Current: {current}\nNeeded: {needed}\nMax: {max_watches}\n"
                        "Increase with: sudo sysctl -w fs.inotify.max_user_watches=524288"
                    )
                })
                return
        except Exception as e:
            self.log(error=e, level="ERROR", block="main_try")


        self.log("[TRIPWIRE] 🔄 Rebuilding watcher table…")
        self._clear_all_watches()
        self.watch_count = 0
        watched_entries = []

        for entry in self._watch_paths:
            base = entry["path"]
            recursive = entry["recursive"]
            watch_dirs = entry["watch_dirs"]
            watch_files = entry["watch_files"]

            if not base or not os.path.exists(base):
                self.log(f"[TRIPWIRE] ⚠ Skipped missing path: {base}")
                continue

            if recursive:
                for dirpath, dirnames, filenames in os.walk(base):
                    # Normalize current path
                    dirpath = os.path.abspath(dirpath)
                    # Skip the current directory entirely
                    if self._is_ignored(dirpath):
                        dirnames[:] = []  # <- don't descend
                        continue

                    # Prune subdirectories
                    dirnames[:] = [d for d in dirnames if not self._is_ignored(os.path.join(dirpath, d))]
                    dirpath = dirpath.decode(errors="ignore") if isinstance(dirpath, bytes) else str(dirpath)
                    filenames = [
                        f.decode(errors="ignore") if isinstance(f, (bytes, bytearray)) else str(f)
                        for f in filenames
                    ]
                    if watch_dirs:
                        if self._safe_add_watch(dirpath):
                            watched_entries.append(dirpath)
                    if watch_files:
                        for fname in filenames:
                            fpath = os.path.join(dirpath, fname)
                            if os.path.isfile(fpath):
                                if self._safe_add_watch(fpath):
                                    watched_entries.append(fpath)
            else:
                if watch_dirs:
                    if self._safe_add_watch(base):
                        watched_entries.append(base)
                if watch_files:
                    try:
                        for fname in os.listdir(base):
                            fpath = os.path.join(base, fname)
                            if os.path.isfile(fpath):
                                if self._safe_add_watch(fpath):
                                    watched_entries.append(fpath)
                    except Exception as e:
                        self.log(f"[TRIPWIRE] ⚠ Unable to list {base}: {e}")

        self.log("[TRIPWIRE] WATCH SUMMARY:")
        for path in watched_entries:
            self.log(f"  • {path}")
        self.log(f"[TRIPWIRE] Total watches: {self.watch_count}")

    def _safe_add_watch(self, path):
        """Safely add an inotify watch for the given path, handling errors if any."""

        WATCH_MASK = (
                inotify.constants.IN_MODIFY |
                inotify.constants.IN_CREATE |
                inotify.constants.IN_DELETE |
                inotify.constants.IN_MOVED_TO |
                inotify.constants.IN_MOVED_FROM
        )

        try:
            if isinstance(path, bytes):
                path = path.decode(errors="replace")
            elif not isinstance(path, str):
                path = str(path)

            self._notifier.add_watch(path, mask=WATCH_MASK)
            self.watch_count += 1
            return True

        except Exception as e:
            self.log(f"[WATCH] Failed for {repr(path)}: {e}")
            return False

    def _normalize_watch_paths(self, paths: list):
        """Normalize and clean the given list of paths into absolute paths."""
        normalized = []

        for entry in paths:
            if isinstance(entry, str):
                normalized.append({
                    "path": entry,
                    "recursive": False,
                    "watch_dirs": True,
                    "watch_files": False
                })

            elif isinstance(entry, dict):
                normalized.append({
                    "path": str(entry.get("path")),
                    "recursive": bool(entry.get("recursive", False)),
                    "watch_dirs": bool(entry.get("watch_dirs", True)),
                    "watch_files": bool(entry.get("watch_files", False)),
                })

        return normalized

    def worker(self, config=None, identity:IdentityObject=None):
        """Main worker function handling file monitoring and taking actions."""
        if not self.running:
            return

        if self._rebuild_flag:
            self._rebuild_flag = False
            #threading = __import__("threading")
            #threading.Thread(target=self._watch_loop, daemon=True).start()

        self._emit_beacon()
        interruptible_sleep(self, self._interval)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()