# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys, os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))


import os, time, subprocess, json, hashlib
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject


class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        try:
            self.AGENT_VERSION = "1.0.0"

            cfg = self.tree_node.get("config", {})

            self.watch_path = cfg.get("watch_path", "/matrix/sora/outbox")
            self.ssh_host = cfg.get("ssh_host")
            self.ssh_port = int(cfg.get("ssh_port", 22))
            self.ssh_user = cfg.get("ssh_user")
            self.remote_path = cfg.get("ssh_path")
            self.auth_type = cfg.get("auth_type")
            self.private_key = cfg.get("private_key")
            self.password = cfg.get("password")

            self.poll_interval = int(cfg.get("poll_interval", 10))

            os.makedirs(self.watch_path, exist_ok=True)

            # delivery DB
            self.db_path = os.path.join(self.path_resolution["comm_path_resolved"],
                                        "sora_delivered.json")
            self.delivered = self._load_db()

            self._emit_beacon = self.check_for_thread_poke(
                "worker", timeout=self.poll_interval * 2, emit_to_file_interval=10
            )

        except Exception as e:
            self.log(error=e, block="init")

    # ---------------------------------------------------------
    def _load_db(self):
        try:
            if os.path.exists(self.db_path):
                return json.load(open(self.db_path))
        except:
            pass
        return {}

    def _save_db(self):
        try:
            with open(self.db_path, "w") as f:
                json.dump(self.delivered, f, indent=2)
        except Exception as e:
            self.log("[SORA][DB][ERROR]", error=e)

    # ---------------------------------------------------------
    def _file_hash(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return "unknown"

    # ---------------------------------------------------------
    def _rsync_file(self, local_file):
        remote = f"{self.ssh_user}@{self.ssh_host}:{self.remote_path}"

        if self.auth_type == "priv":
            cmd = [
                "rsync", "-avz", "-e",
                f"ssh -p {self.ssh_port} -i {self.private_key}",
                local_file, remote
            ]
        else:
            # password authentication (sshpass)
            cmd = [
                "sshpass", "-p", self.password,
                "rsync", "-avz", "-e",
                f"ssh -p {self.ssh_port}",
                local_file, remote
            ]

        self.log(f"[SORA][RSYNC] {' '.join(cmd)}")
        res = subprocess.run(cmd, capture_output=True, text=True)

        if res.returncode != 0:
            self.log(f"[SORA][ERROR] rsync failed: {res.stderr}")
            return False

        self.log("[SORA] Upload complete.")
        return True

    # ---------------------------------------------------------
    def worker(self, config=None, identity: IdentityObject = None):
        try:
            self._emit_beacon()

            # check for config updates
            if config and isinstance(config, dict):
                self.watch_path = config.get("watch_path", self.watch_path)
                self.remote_path = config.get("ssh_path", self.remote_path)
                self.ssh_host = config.get("ssh_host", self.ssh_host)
                self.ssh_user = config.get("ssh_user", self.ssh_user)
                self.ssh_port = int(config.get("ssh_port", self.ssh_port))
                self.auth_type = config.get("auth_type", self.auth_type)
                self.private_key = config.get("private_key", self.private_key)
                self.password = config.get("password", self.password)
                self.poll_interval = int(config.get("poll_interval", self.poll_interval))

            for fname in os.listdir(self.watch_path):
                if not fname.lower().endswith((".mp4", ".webm", ".mov", ".mkv")):
                    continue

                fpath = os.path.join(self.watch_path, fname)

                h = self._file_hash(fpath)
                if h in self.delivered:
                    continue

                self.log(f"[SORA] New file detected: {fname}")

                if self._rsync_file(fpath):
                    self.delivered[h] = {
                        "file": fname,
                        "hash": h,
                        "timestamp": int(time.time())
                    }
                    self._save_db()

                    # swarm alert
                    self.alert_operator(f"SORA upload complete → {fname}")

        except Exception as e:
            self.log("[SORA][ERROR]", error=e)

        interruptible_sleep(self, self.poll_interval)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()