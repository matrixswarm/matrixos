import time
import os
import json
import base64
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from core.python_core.class_lib.packet_delivery.utility.encryption.config import ENCRYPTION_CONFIG

class Logger:
    def __init__(self, log_path, logs="logs", file_name="agent.log", max_bytes=5_000_000, backup_count=5):
        if ENCRYPTION_CONFIG.is_enabled():
            swarm_key = ENCRYPTION_CONFIG.get_swarm_key()
            self._decoded_swarm_key = base64.b64decode(swarm_key) if swarm_key else b''
        self.default_log_file = os.path.join(log_path, logs, file_name)
        os.makedirs(os.path.dirname(self.default_log_file), exist_ok=True)

        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.default_log_file = os.path.join(log_path, logs, file_name)

    def log(
            self,
            message,
            level="INFO",
            print_to_console=True,
            include_timestamp=True,
            override_path=None,
            override_filename=None,
            signer=None,
            console_mode="pretty"
    ):

        try:

            if hasattr(self, "logger"):
                self.logger.log(
                    message=message,
                    level=level,
                    print_to_console=print_to_console,
                    include_timestamp=include_timestamp,
                    override_path=override_path,
                    override_filename=override_filename,
                    signer=signer,
                    console_mode=console_mode
                )
            else:


                # fallback print if logger is missing
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{ts}] [{level}] {message}")


            # 🔧 Build log entry
            log_entry = {
                "level": level,
                "message": message
            }

            if include_timestamp:
                log_entry["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

            if signer:
                try:
                    payload = json.dumps(log_entry, sort_keys=True).encode()
                    log_entry["sig"] = base64.b64encode(signer(payload)).decode()
                except Exception as e:
                    print(f"[LOGGER][WARN] Signature failed: {e}")

            # 📄 Prepare output for disk (JSON always)
            output = json.dumps(log_entry, ensure_ascii=False)

            # 🔐 Encrypt if swarm key is active
            if hasattr(self, "_decoded_swarm_key"):
                output = self._encrypt_line(output)

            # 🖨 Console Output
            if print_to_console:
                if console_mode == "json" or hasattr(self, "_decoded_swarm_key"):
                    print(output)
                else:
                    ts = log_entry.get("timestamp", "")
                    lvl = log_entry.get("level", "INFO")
                    msg = log_entry.get("message", "")
                    emoji = {
                        "INFO": "🔹",
                        "ERROR": "❌",
                        "WARNING": "⚠️",
                        "DEBUG": "🐞"
                    }.get(lvl.upper(), "🔸")
                    print(f"{emoji} [{ts}] [{lvl}] {msg}")

            # 📝 Write to log file (structured)
            path = (
                os.path.join(override_path, override_filename)
                if override_path and override_filename
                else self.default_log_file
            )

            os.makedirs(os.path.dirname(path), exist_ok=True)

            # Check for rotation
            if os.path.exists(path) and os.path.getsize(path) >= self.max_bytes:
                self._rotate_logs(path)

            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(output.rstrip() + "\n")  # force newline, strip extras
            except Exception as e:
                print(f"[LOGGER][ERROR] Failed to write to {path}: {e}")

        except Exception as final_fail:
            # Emergency fallback
            fallback_path = "/tmp/matrixswarm_fallback.log"
            try:
                with open(fallback_path, "a") as f:
                    f.write(f"[LOGGER-FAIL] {datetime.utcnow().isoformat()} :: {final_fail}\n")
            except:
                pass  # If even /tmp fails, let it burn silently

            print(f"🛑 [LOGGER][CRITICAL FAIL] Could not write to main log. Error dumped to: {fallback_path}")


    def _rotate_logs(self, path):
        base = Path(path)
        for i in reversed(range(1, self.backup_count)):
            src = base.with_name(f"{base.stem}.{i}.log")
            dst = base.with_name(f"{base.stem}.{i + 1}.log")
            if src.exists():
                src.rename(dst)
        base.rename(base.with_name(f"{base.stem}.1.log"))

    def _encrypt_line(self, line: str) -> str:
        nonce = get_random_bytes(12)
        cipher = AES.new(self._decoded_swarm_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(line.encode())
        blob = nonce + tag + ciphertext
        return base64.b64encode(blob).decode()

    @staticmethod
    def decrypt_log_line(line, key_bytes):
        try:
            blob = base64.b64decode(line.strip())
            nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
            cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        except Exception as e:
            return f"[DECRYPT-FAIL] {str(e)}"

    def set_encryption_key(self, swarm_key_b64):
        self._decoded_swarm_key = base64.b64decode(swarm_key_b64)

    @staticmethod
    def render_log_line(entry: dict) -> str:
        """
        Convert a JSON log entry into a flat CLI-style string.
        """
        ts = entry.get("timestamp", "")
        level = entry.get("level", "INFO")
        msg = entry.get("message", "")
        return f"[{ts}] [{level}] {msg}"