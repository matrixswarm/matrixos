# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Docstrings by Gemini
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import hashlib
import shutil
import json
import time
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.utils.crypto_utils import encrypt_with_ephemeral_aes, sign_data, pem_fix
from Crypto.PublicKey import RSA

"""
WordPress Plugin Guard Agent: Monitors the integrity of WordPress plugins
by comparing their current file hashes against a trusted baseline snapshot.
It provides functions to snapshot plugins, scan for changes, quarantine
unauthorized changes, and dispatch alerts and RPC responses.
"""
class Agent(BootAgent):
    """
    The WordPress Plugin Guard Agent (Agent) provides automated File Integrity Monitoring (FIM)
    for WordPress plugins by comparing current file SHA256 hashes against a trusted,
    cryptographically signed baseline manifest.

    The agent's primary functions are:
    1.  **Snapshotting:** Creating and managing SHA256 manifests for approved plugins.
    2.  **Scanning (`_scan_plugins`):** Periodically auditing the plugin directory for:
       * **Integrity Alerts:** Changes (modifications, additions, deletions) to tracked plugins.
       * **Untracked Plugins:** New folders without a baseline manifest.
       * **Missing Plugins:** Tracked plugins that have been removed from disk.
    3.  **Enforcement:**
       * **Quarantine:** Moves untracked/modified plugins to a dedicated quarantine directory if 'enforce' is enabled.
       * **Block-New:** Aggressively deletes untracked plugins immediately if 'block_new' is enabled.
    4.  **Communication:** Dispatches general alerts and responds to GUI panel RPC commands with encrypted and signed status updates.

    **Configuration Context (from `config` section):**
    -   **`plugin_dir`**: `/var/www/html/wordpress/wp-content/plugins` (The directory to monitor).
    -   **`quarantine_dir`**: `/opt/quarantine/wp_plugins` (Path for moved plugins).
    -   **`snapshot_root`**: `/opt/swarm/guard/snapshots` (Root for storing baseline manifests).
    -   **`enforce`**: `False` (Initial state of the automatic quarantine feature).
    -   **`interval`**: `15` (Time in seconds between integrity scans).
    -   **`alert_to_role`**: `hive.alert` (Role for agents receiving critical alerts).
    -   **RPC Services Handled:** `snapshot`, `status`, `list_plugins`, `snapshot_plugin`,
       `snapshot_untracked`, `disapprove_plugin`, `enforce`, `restore_plugin`, `block`,
       `quarantine`, and `delete_quarantined`.
    """
    def __init__(self):
        super().__init__()
        try:
            self.name = "wordpress_plugin_guard"
            cfg = self.tree_node.get("config", {})

            self.AGENT_VERSION = "1.0.0"


            # Configurable paths
            self.plugin_dir = cfg.get("plugin_dir", "/var/www/html/wp-content/plugins")
            self.snapshot_root = cfg.get("snapshot_root", "/opt/swarm/guard/snapshots")
            self.site_id = cfg.get("site_id", "site1")
            self.quarantine_dir = os.path.join(cfg.get("quarantine_dir", "/opt/quarantine/wp_plugins"), self.site_id)

            self._signing_keys = self.tree_node.get('config', {}).get('security', {}).get('signing', {})
            self._has_signing_keys = bool(self._signing_keys.get('privkey')) and bool(
                self._signing_keys.get('remote_pubkey'))

            if self._has_signing_keys:
                priv_pem = self._signing_keys.get("privkey")
                priv_pem = pem_fix(priv_pem)
                self._signing_key_obj = RSA.import_key(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)

            self.enforce = bool(cfg.get("enforce", False))
            self.interval = int(cfg.get("interval", 30))
            self.rpc_role = self.tree_node.get("rpc_router_role", "hive.rpc")
            self.alert_role = cfg.get("alert_to_role", None)
            self.report_role = cfg.get("report_to_role", None)
            self.read_only = bool(cfg.get("read_only", False))


            self.block_new = False
            m = self._load_manifest()
            self.block_new = bool(m.get("block_new", self.block_new))
            self.log(f"[PLUGIN-GUARD][INIT] Block-New restored as {self.block_new}", level="INFO")

            m = self._load_manifest()
            self.block_new = bool(m.get("block_new", self.block_new))
            self.enforce = bool(m.get("enforce", self.enforce))
            self.log(f"[PLUGIN-GUARD][INIT] Block-New={self.block_new} Enforce={self.enforce}", level="INFO")

            self._emit_beacon = self.check_for_thread_poke("worker", timeout=90, emit_to_file_interval=10)
            self.last_alerts = {}


        except Exception as e:
            self.log("[PLUGIN-GUARD][INIT]", error=e, level="CRITICAL")

    def post_boot(self):
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – watching the plugins, because someone has to.")

    # === Helpers ===
    def _sha256_file(self, path):
        """
        Computes the SHA256 hash of a file.

        Args:
            path (str): The full path to the file.

        Returns:
            str: The hexadecimal SHA256 digest.
        """
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    def _normalize_folder_name(self, folder):
        """
        Normalizes a plugin folder name by removing common suffixes (e.g.,
        'akismet_1234' becomes 'akismet'), often added during auto-updates.

        Args:
            folder (str): The name of the plugin folder.

        Returns:
            str: The normalized plugin name.
        """
        # WP auto-updates append suffixes (e.g., akismet_1234 → akismet)
        return folder.split("_")[0]

    def _snapshot_plugin(self, plugin_folder, out_path):
        """
        Creates a file integrity manifest (SHA256 hashes) for a single plugin.

        The manifest is a JSON file mapping relative file paths to their hashes.

        Args:
            plugin_folder (str): The full path to the plugin's root directory.
            out_path (str): The file path where the JSON manifest will be saved.

        Returns:
            dict: The generated manifest data.
        """
        manifest = {}
        for root, dirs, files in os.walk(plugin_folder):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, plugin_folder).replace("\\", "/")
                manifest[rel] = self._sha256_file(fpath)
        self._ensure_dir(os.path.dirname(out_path))

        def writer():
            with open(out_path, "w") as f:
                json.dump(manifest, f, indent=2)

        self._safe_write(out_path, writer)

        return manifest

    def _snapshot_all_plugins(self):
        """
        Refreshes baseline only for already tracked plugins.
        New/untracked plugins are left out until explicitly approved.
        """
        out_dir = os.path.join(self.snapshot_root, self.site_id)
        self._ensure_dir(out_dir)

        tracked = {f[:-5] for f in os.listdir(out_dir) if f.endswith(".json")}
        for folder in os.listdir(self.plugin_dir):
            fpath = os.path.join(self.plugin_dir, folder)
            if not os.path.isdir(fpath):
                continue
            norm_name = self._normalize_folder_name(folder)
            if norm_name not in tracked:
                self.log(f"[PLUGIN-GUARD][SNAPSHOT] Skipping untracked plugin {folder}", level="INFO")
                continue
            manifest_path = os.path.join(out_dir, f"{norm_name}.json")
            self._snapshot_plugin(fpath, manifest_path)


            manifest = self._load_manifest()
            tracked = manifest["tracked_plugins"].keys()
            for plugin in tracked:
                fpath = os.path.join(self.plugin_dir, plugin)
                if not os.path.isdir(fpath):
                    continue
                norm = self._normalize_folder_name(plugin)
                out_path = os.path.join(self.snapshot_root, self.site_id, f"{norm}.json")
                self._snapshot_plugin(fpath, out_path)

        self.log(f"[PLUGIN-GUARD] Refreshed snapshot for {len(tracked)} tracked plugins at site {self.site_id}")



    def _compare_plugin(self, folder):
        """
        Compares the current files and hashes of a plugin against its
        trusted baseline manifest.

        Args:
            folder (str): The name of the plugin folder to check.

        Returns:
            tuple: (bool, str) - True if clean, False if changes detected,
                   and a string describing the outcome/reason.
        """
        out_dir = os.path.join(self.snapshot_root, self.site_id)
        norm_name = self._normalize_folder_name(folder)
        manifest_path = os.path.join(out_dir, f"{norm_name}.json")
        fpath = os.path.join(self.plugin_dir, folder)

        if not os.path.exists(manifest_path):
            return False, "New or unknown plugin — never trusted."

        with open(manifest_path, "r") as f:
            baseline = json.load(f)

        current = {}
        for root, dirs, files in os.walk(fpath):
            for fname in files:
                rel = os.path.relpath(os.path.join(root, fname), fpath).replace("\\", "/")
                current[rel] = self._sha256_file(os.path.join(root, fname))

        changed = [k for k in current if k in baseline and current[k] != baseline[k]]
        added   = [k for k in current if k not in baseline]
        deleted = [k for k in baseline if k not in current]

        if changed or added or deleted:
            return False, "Plugin files were changed since last trusted baseline."
        return True, "Clean"

    # === Core Scan ===
    def _scan_plugins(self):
        """
        The main scan logic. Iterates through all plugins, compares against manifests,
        and alerts on anomalies:
          - Changed files
          - New/untrusted plugin folders (no manifest)
          - Trusted plugins missing from disk
        Also quarantines if enforcement is enabled.
        """
        manifest = self._load_manifest()
        try:
            # refresh persisted states first
            self.block_new = bool(manifest.get("block_new", self.block_new))
            self.enforce = bool(manifest.get("enforce", self.enforce))
        except Exception as e:
            self.log(f"[PLUGIN-GUARD][SCAN] Failed to refresh states: {e}", level="WARN")


        try:
            entries = os.listdir(self.plugin_dir)
            existing = set(entries)

            # --- cleanup stale manifest records ---
            changed = False

            for name in list(manifest["tracked_plugins"].keys()):
                if name not in existing:
                    self.log(f"[PLUGIN-GUARD][CLEANUP] 🧹 Removing stale tracked record for {name}", level="INFO")
                    del manifest["tracked_plugins"][name]
                    changed = True

            for name in list(manifest["untracked_plugins"].keys()):
                if name not in existing:
                    self.log(f"[PLUGIN-GUARD][CLEANUP] 🧹 Removing stale untracked record for {name}", level="INFO")
                    del manifest["untracked_plugins"][name]
                    changed = True

            if changed:
                self._save_manifest(manifest)
                self.log(f"[PLUGIN-GUARD][CLEANUP] Manifest pruned of stale entries.", level="INFO")

        except Exception as e:
            self.log("[PLUGIN-GUARD] Failed to list plugin dir", error=e)
            return

        try:
            out_dir = os.path.join(self.snapshot_root, self.site_id)
            self._ensure_dir(out_dir)

            # Collect known manifests
            snapshots = {f[:-5] for f in os.listdir(out_dir)
                         if f.endswith(".json") and not f.startswith(".")}

            # Map normalized names to actual folders
            current_plugins = {
                self._normalize_folder_name(f): f
                for f in entries
                if os.path.isdir(os.path.join(self.plugin_dir, f))
            }

            # === Step 1: Check each folder on disk ===
            for norm, folder in current_plugins.items():
                fpath = os.path.join(self.plugin_dir, folder)
                manifest_path = os.path.join(out_dir, f"{norm}.json")

                if not os.path.exists(manifest_path):
                    info = {
                        "plugin": folder,
                        "path": fpath,
                        "reason": "Plugin folder present but no baseline manifest exists.",
                        "enforce": self.enforce,
                        "timestamp": int(time.time())
                    }

                    self.log(f"[PLUGIN-GUARD][DIR-AUDIT] 🚨 Untrusted plugin detected: {folder}", level="WARN")

                    # prioritize block-new over enforce, but never both
                    if self.block_new and not getattr(self, "_suppress_alerts", False):
                        try:
                            shutil.rmtree(fpath)
                            self.log(f"[PLUGIN-GUARD][BLOCK] ❌ Deleted untracked plugin {folder} instantly.",
                                     level="CRITICAL")
                            self.drop_alert({
                                "plugin": folder,
                                "path": fpath,
                                "reason": "Untracked plugin deleted under Block-New enforcement.",
                                "action": "auto_delete",
                                "enforce": self.enforce,
                                "timestamp": int(time.time())
                            })
                            continue
                        except Exception as be:
                            self.log(f"[PLUGIN-GUARD][BLOCK][ERROR] Failed to delete {folder}: {be}", level="ERROR")

                    elif self.enforce:
                        try:
                            self._quarantine(folder, fpath)
                            self.log(f"[PLUGIN-GUARD][ENFORCE] 🚨 Quarantined untracked plugin {folder}.", level="WARN")
                            continue
                        except Exception as qe:
                            self.log(f"[PLUGIN-GUARD][ENFORCE][ERROR] Failed to quarantine {folder}: {qe}",
                                     level="ERROR")

                    else:
                        self.log(f"[PLUGIN-GUARD][BLOCK] No enforcement active; leaving {folder} in place.",
                                 level="INFO")

                    if not getattr(self, "_suppress_alerts", False) and self.should_alert(folder):
                        self.drop_alert(info)

                    if self.enforce:
                        self._quarantine(folder, fpath)



            # === Step 2: Check for deleted plugins (manifest exists but no folder) ===
            for snap in snapshots:
                found = any(self._normalize_folder_name(f) == snap for f in entries)
                if not found:
                    info = {
                        "plugin": snap,
                        "reason": "Trusted plugin missing from disk.",
                        "timestamp": int(time.time())
                    }
                    self.log(f"[PLUGIN-GUARD][DIR-AUDIT] ⚠️ Trusted plugin missing from disk: {snap}", level="WARN")
                    if self.should_alert(snap):
                        self.drop_alert(info)

        except Exception as e:
            self.log("[PLUGIN-GUARD] Failed to list plugin dir", error=e)
            return

    def cmd_toggle_block(self, content, packet, identity=None):
        req = packet.get("content", {})
        enable = bool(req.get("block_new", not self.block_new))
        self.block_new = enable

        manifest = self._load_manifest()
        manifest["block_new"] = self.block_new
        self._save_manifest(manifest)

        if self.block_new:
            # warn operator before the scan loop enforces
            self.log("[PLUGIN-GUARD][WARN] ⚠️ Block-New enabled. "
                     "All untracked plugins will be deleted on next scan.", level="WARN")

            self._suppress_alerts = True
            try:
                self.drop_alert({
                    "plugin": "system",
                    "path": self.plugin_dir,
                    "reason": "Operator enabled Block-New mode. "
                              "All untracked plugins will be deleted on next scan.",
                    "enforce": self.enforce,
                    "action": "mode_change",
                    "timestamp": int(time.time())
                })
            finally:
                self._suppress_alerts = False

        else:
            self.log("[PLUGIN-GUARD][INFO] Block-New disabled. "
                     "Untracked plugins will no longer be automatically deleted.", level="INFO")

        self._cmd_list_alert_status(
            req.get("session_id", "none"),
            req.get("token"),
            req.get("return_handler", "plugin_guard.panel.update"),
        )

    def _quarantine(self, folder, fpath):
        """
        Moves an unauthorized or modified plugin folder to the configured
        quarantine directory and logs the action.

        Args:
            folder (str): The name of the plugin folder.
            fpath (str): The full path to the plugin to be moved.
        """
        try:
            self._ensure_dir(self.quarantine_dir)
            qpath = os.path.join(self.quarantine_dir, f"{folder}_{int(time.time())}")
            shutil.move(fpath, qpath)
            self.log(f"[PLUGIN-GUARD] Quarantined {folder} → {qpath}")
        except Exception as e:
            fallback = f"{qpath}.failcopy"
            self.log(f"[PLUGIN-GUARD][QUARANTINE][FAIL] Move failed: {e}; attempting fallback copy → {fallback}",
                     level="ERROR")
            try:
                shutil.copytree(fpath, fallback)
                shutil.rmtree(fpath)
                self.log(f"[PLUGIN-GUARD][QUARANTINE] Fallback succeeded: copied to {fallback}", level="WARN")
            except Exception as final_e:
                self.log(f"[PLUGIN-GUARD][QUARANTINE][FATAL] Fallback copy also failed: {final_e}", level="CRITICAL")

    def should_alert(self, key):
        """
        Implements a basic one-time alert mechanism: only alerts if the key
        (the plugin folder name) has not been alerted on before in this session.

        Args:
            key (str): The unique identifier (plugin folder name).

        Returns:
            bool: True if an alert should be sent, False otherwise.
        """
        if key in self.last_alerts:
            return False
        self.last_alerts[key] = time.time()
        return True

    # === Alert Dispatch (Gatekeeper style) ===
    def drop_alert(self, info: dict):
        """
        Constructs and dispatches a general notification alert packet to agents
        with the configured 'alert_to_role'.

        Args:
            info (dict): A dictionary containing plugin details (plugin name,
                         path, reason, and enforcement status).
        """
        try:
            endpoints = self.get_nodes_by_role(self.alert_role)
            if not endpoints:
                self.log("[PLUGIN-GUARD][ALERT] No alert-compatible agents found.", level="WARN")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk2 = self.get_delivery_packet("notify.alert.general")

            msg_text = (
                f"🧹 WordPress Plugin Guard Alert\n\n"
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

            details = {
                "plugin": info.get("plugin"),
                "path": info.get("path"),
                "reason": info.get("reason"),
                "action": info.get("action", "detected"),
                "hash": info.get("hash"),
                "enforce": info.get("enforce"),
                "timestamp": info.get("timestamp", int(time.time()))
            }
            metrics = {"plugin_guard": info}
            self.send_status_report('plugin_integrity_alert', 'CRITICAL', details, metrics)

        except Exception as e:
            self.log(error=e, block="drop_alert", level="ERROR")


    # === RPC Commands ===
    def cmd_list_plugins(self, content, packet, identity=None):
        """
        RPC command to list the names of all plugin folders currently present
        on the disk. The result is broadcasted back via `_broadcast_output`.
        """
        req = packet.get("content", {})
        session_id = req.get("session_id", "none")
        token = req.get("token", str(int(time.time())))
        return_handler = req.get("return_handler", "plugin_guard.panel.update")

        plugins = []
        for folder in os.listdir(self.plugin_dir):
            fpath = os.path.join(self.plugin_dir, folder)
            if os.path.isdir(fpath):
                plugins.append(folder)

        self._broadcast_output(
            {"plugins": plugins},
            handler=return_handler,
            session_id=session_id,
            token=token
        )

    def cmd_enforce(self, content, packet, identity=None):
        """
        RPC command to toggle enforcement mode on or off.
        Persists state in manifest and notifies operator.
        """
        try:
            req = packet.get("content", {})
            # If enforce is included, use it; otherwise flip current state
            if "enforce" in req:
                enable = bool(req.get("enforce"))
            else:
                enable = not self.enforce

            self.enforce = enable
            manifest = self._load_manifest()
            manifest["enforce"] = self.enforce
            self._save_manifest(manifest)
            self.log(f"[PLUGIN-GUARD] Persisted enforce={self.enforce} to manifest", level="INFO")

            # operator log + alert
            if self.enforce:
                self.log("[PLUGIN-GUARD][WARN] ⚔️ Enforcement enabled. "
                         "Untracked or modified plugins will be moved to quarantine on next scan.",
                         level="WARN")

                try:
                    self._suppress_alerts = True
                    self.drop_alert({
                        "plugin": "system",
                        "path": self.plugin_dir,
                        "reason": "Operator enabled Enforcement mode. "
                                  "Untracked or modified plugins will be quarantined on next scan.",
                        "enforce": self.enforce,
                        "action": "mode_change",
                        "timestamp": int(time.time())
                    })
                finally:
                    self._suppress_alerts = False


            else:
                self.log("[PLUGIN-GUARD][INFO] Enforcement disabled. "
                         "No automatic quarantines will occur.", level="INFO")

            # send updated state to panel
            return_handler = req.get("return_handler", "plugin_guard.panel.update")
            session_id = req.get("session_id", "none")
            token = req.get("token", str(int(time.time())))
            self._cmd_list_alert_status(session_id, token, return_handler)

        except Exception as e:
            self.log("[PLUGIN-GUARD][ERROR] cmd_enforce failed", error=e)

    def cmd_snapshot_plugin(self, content, packet, identity=None):
        """
        Approve and snapshot a single plugin folder (like 'git add <plugin>').
        """
        req = packet.get("content", {})
        plugin = req.get("plugin")
        session_id = req.get("session_id", "none")
        token = req.get("token", str(int(time.time())))
        return_handler = req.get("return_handler", "plugin_guard.panel.update")

        self._suppress_alerts = True
        try:
            if not plugin:
                self.log("[PLUGIN-GUARD] No plugin specified for approval", level="WARN")
                return

            fpath = os.path.join(self.plugin_dir, plugin)
            if not os.path.isdir(fpath):
                self.log(f"[PLUGIN-GUARD] Plugin {plugin} not found on disk", level="WARN")
                return

            norm_name = self._normalize_folder_name(plugin)
            fpath = os.path.join(self.plugin_dir, norm_name)

            out_dir = os.path.join(self.snapshot_root, self.site_id)
            self._ensure_dir(out_dir)
            norm_name = self._normalize_folder_name(plugin)
            manifest_path = os.path.join(out_dir, f"{norm_name}.json")

            self._snapshot_plugin(fpath, manifest_path)
            self.log(f"[PLUGIN-GUARD][SNAPSHOT] Approved plugin {plugin} → {manifest_path}")

            manifest = self._load_manifest()
            self._register_plugin(manifest, plugin, norm_name)


            # --- Cleanup: remove from untracked if present ---
            if plugin in manifest.get("untracked_plugins", {}):
                del manifest["untracked_plugins"][plugin]
            if norm_name in manifest.get("untracked_plugins", {}):
                del manifest["untracked_plugins"][norm_name]
            self._save_manifest(manifest)

            self._cmd_list_alert_status(session_id, token, return_handler)
        finally:
            self._suppress_alerts = False

    def _manifest_path(self):
        return os.path.join(self.snapshot_root, self.site_id, ".manifest.json")

    def _load_manifest(self):

        path = self._manifest_path()

        r={
            "site": self.site_id,
            "tracked_plugins": {},
            "untracked_plugins": {},
            "block_new": False
        }

        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.load(f)
            if "untracked_plugins" not in data:
                data["untracked_plugins"] = {}
            if "block_new" not in data:
                data["block_new"] = False
            if "enforce" not in data:
                data["enforce"] = False
            return data

        return r

    def _save_manifest(self, manifest):
        path = self._manifest_path()
        self._ensure_dir(os.path.dirname(path))

        self._safe_write(
            path,
            lambda: json.dump(manifest, open(path, "w"), indent=2)
        )

    def cmd_snapshot_untracked(self, content, packet, identity=None):
        """
        Approve and snapshot all untracked plugin folders (like 'git add .').
        """
        self._suppress_alerts = True
        try:
            req = packet.get("content", {})
            session_id = req.get("session_id", "none")
            token = req.get("token", str(int(time.time())))
            return_handler = req.get("return_handler", "plugin_guard.panel.update")

            out_dir = os.path.join(self.snapshot_root, self.site_id)
            self._ensure_dir(out_dir)
            tracked = {f[:-5] for f in os.listdir(out_dir) if f.endswith(".json")}

            approved = []
            manifest = self._load_manifest()
            for folder in os.listdir(self.plugin_dir):
                fpath = os.path.join(self.plugin_dir, folder)
                if not os.path.isdir(fpath):
                    continue
                norm_name = self._normalize_folder_name(folder)
                if norm_name in tracked:
                    continue
                manifest_path = os.path.join(out_dir, f"{norm_name}.json")
                self._snapshot_plugin(fpath, manifest_path)
                approved.append(folder)
                self.log(f"[PLUGIN-GUARD][SNAPSHOT] Approved new plugin {folder} → {manifest_path}")

                self._register_plugin(manifest, folder, norm_name)
                self._save_manifest(manifest)

            self._broadcast_output(
                {"approved_plugins": approved, "snapshot_done": True},
                handler=return_handler,
                session_id=session_id,
                token=token
            )
        finally:
            self._suppress_alerts = False

    def cmd_snapshot_plugins(self, content, packet, identity=None):
        """
        RPC command to refresh snapshot of all *tracked* plugins.
        Does NOT auto-trust new/untracked ones.
        """
        self._snapshot_all_plugins()

        req = packet.get("content", {})
        session_id = req.get("session_id", "none")
        token = req.get("token", str(int(time.time())))
        return_handler = req.get("return_handler", "plugin_guard.panel.update")

        plugins = []
        for folder in os.listdir(self.plugin_dir):
            fpath = os.path.join(self.plugin_dir, folder)
            if os.path.isdir(fpath):
                plugins.append(folder)

        self._broadcast_output(
            {"plugins": plugins, "snapshot_done": True},
            handler=return_handler,
            session_id=session_id,
            token=token
        )

    def cmd_disapprove_plugin(self, content, packet, identity=None):
        """
        Remove a plugin from tracked list.
        If 'manual_quarantine' flag is True, also move it to quarantine.
        """
        self._suppress_alerts = True
        try:
            req = packet.get("content", {})
            plugin = req.get("plugin")
            do_quarantine = bool(req.get("manual_quarantine", False))

            session_id = req.get("session_id", "none")
            token = req.get("token", str(int(time.time())))
            return_handler = req.get("return_handler", "plugin_guard.panel.update")

            if not plugin:
                self.log("[PLUGIN-GUARD] No plugin specified for disapproval", level="WARN")
                return

            manifest = self._load_manifest()
            tracked = manifest.get("tracked_plugins", {})
            untracked = manifest.get("untracked_plugins", {})

            # --- Drop from tracked
            if plugin in tracked:
                norm = tracked[plugin]["normalized"]
                manifest_file = os.path.join(self.snapshot_root, self.site_id, f"{norm}.json")
                if os.path.exists(manifest_file):
                    os.remove(manifest_file)
                del tracked[plugin]
                self.log(f"[PLUGIN-GUARD][SNAPSHOT] Disapproved {plugin}, baseline removed.", level="INFO")

            # --- Manifest cleanup
            if plugin in untracked:
                del untracked[plugin]
            self._save_manifest(manifest)

            # --- Push full refresh ---
            self._cmd_list_alert_status(session_id, token, return_handler)

        except Exception as e:
            self.log("[PLUGIN-GUARD][ERROR] cmd_disapprove_plugin failed", error=e)
        finally:
            self._suppress_alerts = False


    def cmd_quarantine_plugin(self, content, packet, identity=None):
        """
        Move a plugin (tracked or untracked) directly to quarantine.
        """
        try:
            req = packet.get("content", {})
            plugin = req.get("plugin")
            session_id = req.get("session_id", "none")
            token = req.get("token", str(int(time.time())))
            return_handler = req.get("return_handler", "plugin_guard.panel.update")

            if not plugin:
                self.log("[PLUGIN-GUARD] No plugin specified for quarantine", level="WARN")
                return

            fpath = os.path.join(self.plugin_dir, plugin)
            if not os.path.isdir(fpath):
                self.log(f"[PLUGIN-GUARD][QUARANTINE] Plugin {plugin} not found in plugins directory.", level="WARN")
                return

            self._ensure_dir(self.quarantine_dir)
            qpath = os.path.join(self.quarantine_dir, f"{plugin}_{int(time.time())}")

            try:
                shutil.move(fpath, qpath)
                self.log(f"[PLUGIN-GUARD][QUARANTINE] Moved {plugin} → {qpath}", level="WARN")
            except Exception as qe:
                self.log(f"[PLUGIN-GUARD][ERROR] Failed to move {plugin} to quarantine: {qe}", level="ERROR")
                return

            # update manifest: remove from both tracked/untracked
            manifest = self._load_manifest()
            if plugin in manifest.get("tracked_plugins", {}):
                del manifest["tracked_plugins"][plugin]
            if plugin in manifest.get("untracked_plugins", {}):
                del manifest["untracked_plugins"][plugin]
            self._save_manifest(manifest)

            self._cmd_list_alert_status(session_id, token, return_handler)

        except Exception as e:
            self.log("[PLUGIN-GUARD][ERROR] cmd_quarantine_plugin failed", error=e)

    def cmd_delete_quarantined_plugin(self, content, packet, identity=None):
        """
        Permanently delete a quarantined plugin folder.
        """
        try:
            req = packet.get("content", {})
            plugin = req.get("plugin")
            session_id = req.get("session_id", "none")
            token = req.get("token", str(int(time.time())))
            return_handler = req.get("return_handler", "plugin_guard.panel.update")

            if not plugin:
                self.log("[PLUGIN-GUARD] No plugin specified for deletion.", level="WARN")
                return

            qpath = os.path.join(self.quarantine_dir, plugin)
            if not os.path.isdir(qpath):
                self.log(f"[PLUGIN-GUARD][DELETE] Plugin {plugin} not found in quarantine.", level="WARN")
                return

            try:
                shutil.rmtree(qpath)
                self.log(f"[PLUGIN-GUARD][DELETE] Permanently deleted quarantined plugin {plugin}", level="CRITICAL")
            except Exception as de:
                self.log(f"[PLUGIN-GUARD][ERROR] Failed to delete {plugin}: {de}", level="ERROR")
                return

            # cleanup manifest in case any ghost entries linger
            manifest = self._load_manifest()
            for key in ["tracked_plugins", "untracked_plugins"]:
                if plugin in manifest.get(key, {}):
                    del manifest[key][plugin]
            self._save_manifest(manifest)

            # refresh panel
            self._cmd_list_alert_status(session_id, token, return_handler)

        except Exception as e:
            self.log("[PLUGIN-GUARD][ERROR] cmd_delete_quarantined_plugin failed", error=e)

    def cmd_restore_plugin(self, content, packet, identity=None):
        """
        Move a quarantined plugin back to the active plugins directory.
        """
        self._suppress_alerts = True
        try:
            req = packet.get("content", {})
            plugin = req.get("plugin")
            session_id = req.get("session_id", "none")
            token = req.get("token", str(int(time.time())))
            return_handler = req.get("return_handler", "plugin_guard.panel.update")

            qsrc = os.path.join(self.quarantine_dir, plugin)
            if not os.path.exists(qsrc):
                self.log(f"[PLUGIN-GUARD][RESTORE] Plugin {plugin} not found in quarantine.", level="WARN")
                return

            dst = os.path.join(self.plugin_dir, plugin.split("_")[0])
            shutil.move(qsrc, dst)
            self.log(f"[PLUGIN-GUARD][RESTORE] Restored {plugin} → {dst}")

            # --- Auto-trust restored plugin ---
            norm_name = self._normalize_folder_name(plugin)
            manifest_path = os.path.join(self.snapshot_root, self.site_id, f"{norm_name}.json")
            fpath = os.path.join(self.plugin_dir, plugin)

            if os.path.isdir(fpath):
                self._snapshot_plugin(fpath, manifest_path)

                manifest = self._load_manifest()
                manifest["tracked_plugins"][norm_name] = {
                    "normalized": norm_name,
                    "manifest_file": f"{norm_name}.json",
                    "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "approved_by": "commander",
                }

                if plugin in manifest["tracked_plugins"]:
                    del manifest["tracked_plugins"][plugin]

                # clear any lingering untracked record
                if norm_name in manifest.get("untracked_plugins", {}):
                    del manifest["untracked_plugins"][norm_name]

                self._save_manifest(manifest)
                self.log(f"[PLUGIN-GUARD][RESTORE] Auto-trusted {plugin} after restore.")

            self._cmd_list_alert_status(session_id, token, return_handler)

        except Exception as e:
            self.log("[PLUGIN-GUARD][ERROR] cmd_restore_plugin failed", error=e)
        finally:
            self._suppress_alerts = False


    def cmd_list_alert_status(self, content, packet, identity=None):
        """
        RPC command to list plugin status:
          - tracked_clean
          - tracked_alerts (failed integrity)
          - untracked (no manifest)
          - quarantined
        """
        try:
            req = packet.get("content", {})
            session_id = req.get("session_id", "none")
            token = req.get("token", str(int(time.time())))
            return_handler = req.get("return_handler", "plugin_guard.panel.update")

            self._cmd_list_alert_status(session_id, token, return_handler)
        except Exception as e:
            self.log(error=e, block="cmd_list_alert_status")

    def _cmd_list_alert_status(self, session_id="none", token=None, return_handler="plugin_guard.panel.update"):
        """
        Internal version of cmd_list_alert_status so other commands can trigger a full panel refresh.
        """
        out_dir = os.path.join(self.snapshot_root, self.site_id)
        self._ensure_dir(out_dir)

        manifest = self._load_manifest()
        tracked = list(manifest["tracked_plugins"].keys())
        untracked_meta = manifest["untracked_plugins"]

        tracked_clean, tracked_alerts, untracked = [], {}, []

        for folder in os.listdir(self.plugin_dir):
            fpath = os.path.join(self.plugin_dir, folder)
            if not os.path.isdir(fpath):
                continue

            if folder in tracked:
                ok, reason = self._compare_plugin(folder)
                if ok:
                    tracked_clean.append(folder)
                else:
                    tracked_alerts[folder] = {"reason": reason}
                continue

            # outsider
            untracked.append(folder)
            if folder not in untracked_meta or not untracked_meta[folder].get("alerted"):
                info = {
                    "plugin": folder,
                    "path": fpath,
                    "reason": "New plugin folder present but not tracked",
                    "timestamp": int(time.time()),
                    "enforce": self.enforce,
                }
                self.log(f"[PLUGIN-GUARD][DIR-AUDIT] 🚨 Untracked plugin detected: {folder}", level="WARN")

                if not getattr(self, "_suppress_alerts", False) and self.should_alert(folder):
                    self.drop_alert(info)

                untracked_meta[folder] = {
                    "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "alerted": True,
                }
                self._save_manifest(manifest)

        quarantined = []
        if os.path.exists(self.quarantine_dir):
            for folder in os.listdir(self.quarantine_dir):
                qpath = os.path.join(self.quarantine_dir, folder)
                if os.path.isdir(qpath):
                    quarantined.append(folder)

        scan_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._broadcast_output(
            {
                "tracked_clean": tracked_clean,
                "tracked_alerts": tracked_alerts,
                "untracked": untracked,
                "quarantined_plugins": quarantined,
                "block_new": self.block_new,
                "enforce_state": self.enforce,
                "last_scan": scan_time,
            },
            handler=return_handler,
            session_id=session_id,
            token=token,
        )

    def _broadcast_output(self, output, handler="plugin_guard.panel.update",session_id="none", token=None):
        """
        Encrypts, signs, and dispatches an RPC response packet to the
        configured RPC router role.

        Args:
            output (dict): The data payload to send back.
            handler (str): The handler to be executed on the receiving end.
            session_id (str): The session identifier for the request.
            token (str): A token for tracking the response.
        """
        try:
            endpoints = self.get_nodes_by_role(self.rpc_role, return_count=1)
            if not endpoints:
                self.log("[PLUGIN-GUARD] ❌ No hive.rpc endpoints found")
                return

            remote_pub_pem = self.tree_node.get("config", {}).get("security", {}).get("signing", {}).get("remote_pubkey")

            payload = {
                "handler": handler,
                "content": {
                    "session_id": session_id,
                    "token": token,
                    **output,
                    "timestamp": int(time.time())
                }
            }

            #self.log(f"[PLUGIN-GUARD][DEBUG] Outgoing payload: {json.dumps(payload, indent=2)}")
            sealed = encrypt_with_ephemeral_aes(payload, remote_pub_pem)
            content = {
                "serial": self.tree_node.get("serial", {}),
                "content": sealed,
                "timestamp": int(time.time()),
            }
            sig = sign_data(content, self._signing_key_obj)
            content["sig"] = sig

            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": "dummy_handler",
                "origin": self.command_line_args["universal_id"],
                "session_id": session_id,
                "content": content,
            })

            for ep in endpoints:
                pk.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk, ep.get_universal_id())

            self.log("[PLUGIN-GUARD] Broadcasted panel output")


        except Exception as e:
            self.log("[PLUGIN-GUARD][ERROR] Broadcast failed", error=e)

    def send_status_report(self, status, severity, details, metrics=None):
        """
        Sends a structured status event packet to the configured role for forensic ingestion.
        Mirrors Gatekeeper's style.
        """
        try:
            if not self.report_role:
                self.log("[PLUGIN-GUARD] No report_to_role configured, skipping status report.", level='WARN')
                return

            endpoints = self.get_nodes_by_role(self.report_role)
            if not endpoints:
                self.log(f"[PLUGIN-GUARD] No endpoints found for role '{self.report_role}'", level='WARN')
                return

            pk_inner = self.get_delivery_packet("standard.status.event.packet")
            pk_inner.set_data({
                "source_agent": self.command_line_args.get("universal_id", "plugin_guard"),
                "service_name": "wordpress.plugins",
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

            self.log(f"[PLUGIN-GUARD] Structured status report sent to role '{self.report_role}'", level='INFO')

        except Exception as e:
            self.log(f"[PLUGIN-GUARD][ERROR] send_status_report failed: {e}", level='ERROR')

    def _ensure_dir(self, path):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            self.log(f"[PLUGIN-GUARD][ERROR] Failed to create dir: {path} – {e}", level="ERROR")

    def _register_plugin(self, manifest, plugin, norm_name):
        manifest["tracked_plugins"][plugin] = {
            "normalized": norm_name,
            "manifest_file": f"{norm_name}.json",
            "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "approved_by": "commander"
        }

    def _safe_write(self, path, write_func, op_name="write", *args, **kwargs):
        """
        Attempts a safe write operation. Alerts the operator on permission issues
        or disk I/O errors that prevent successful file writes.

        Args:
            path (str): Path being written to (for alert/log context)
            write_func (callable): The function performing the write
            *args, **kwargs: Passed directly to write_func
        """
        if self.read_only:
            self.log(f"[PLUGIN-GUARD][READONLY] 🔒 Write skipped for {path} (read-only mode)", level="WARN")
            return

        try:
            return write_func(*args, **kwargs)
        except PermissionError as pe:
            msg = f"🚫 Permission denied while writing {path} failed on {path}"
            self.log(f"[PLUGIN-GUARD][PERM] {msg}: {pe}", level="ERROR")
            self.drop_alert({
                "plugin": "system",
                "path": path,
                "reason": msg,
                "action": "permission_error",
                "enforce": self.enforce,
                "timestamp": int(time.time())
            })
        except OSError as oe:
            msg = f"💾 OS error while writing {path}: {oe.strerror}"
            self.log(f"[PLUGIN-GUARD][IO] {msg}", level="ERROR")
            self.drop_alert({
                "plugin": "system",
                "path": path,
                "reason": msg,
                "action": "write_failed",
                "enforce": self.enforce,
                "timestamp": int(time.time())
            })
        except Exception as e:
            msg = f"⚠️ Unexpected error while writing {path}: {e}"
            self.log(f"[PLUGIN-GUARD][IO] {msg}", level="ERROR")
            self.drop_alert({
                "plugin": "system",
                "path": path,
                "reason": msg,
                "action": "write_exception",
                "enforce": self.enforce,
                "timestamp": int(time.time())
            })

    # === Worker ===
    def worker(self, config=None, identity=None):
        """
        The main loop for the agent. It runs the integrity scan (`_scan_plugins`)
        and then sleeps for the configured interval.

        Args:
            config (dict, optional): Configuration passed to the worker.
            identity (IdentityObject, optional): The agent's identity.
        """
        self._emit_beacon()
        self._scan_plugins()
        interruptible_sleep(self, self.interval)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
