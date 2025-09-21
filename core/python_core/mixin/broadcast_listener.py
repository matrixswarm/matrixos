# BroadcastListenerMixin — watches the /broadcast/ folder and routes to handlers
import os
import json
import time

class BroadcastListenerMixin:
    def start_broadcast_listener(self):
        broadcast_path = os.path.join(self.path_resolution["comm_path_resolved"], "broadcast")
        os.makedirs(broadcast_path, exist_ok=True)
        self.log("[BROADCAST] Listening for broadcast payloads...")

        while self.running:
            try:
                for fname in os.listdir(broadcast_path):
                    if not fname.startswith("broadcast_") or not fname.endswith(".json"):
                        continue
                    fpath = os.path.join(broadcast_path, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        try:
                            data = json.load(f)
                        except Exception as e:
                            self.log(f"[BROADCAST][FAIL] Invalid broadcast file {fname}: {e}")
                            continue

                    command = data.get("command") or data.get("event") or data.get("type")
                    if command:
                        handler_name = f"on_broadcast_{command}"
                        if hasattr(self, handler_name):
                            try:
                                getattr(self, handler_name)(data)
                                self.log(f"[BROADCAST] Handled: {command}")
                            except Exception as e:
                                self.log(f"[BROADCAST][ERROR] {handler_name} crashed: {e}")
                        else:
                            self.log(f"[BROADCAST][MISS] No handler for: {command}")

                    os.remove(fpath)
            except Exception as e:
                self.log(f"[BROADCAST][LOOP-ERROR] {e}")
            time.sleep(2)