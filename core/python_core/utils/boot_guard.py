import os
import re
import psutil

def validate_universe_id(uid):
    pattern = r"^[a-zA-Z0-9_-]{1,32}$"
    if not re.match(pattern, uid):
        print(f"[BLOCKED] Invalid universe ID: '{uid}'")
        os._exit(1)

def enforce_single_matrix_instance(universe_id):
    label = f"--job {universe_id}:site_boot:matrix:matrix"
    for proc in psutil.process_iter(['cmdline']):
        try:
            cmdline = " ".join(proc.info.get("cmdline") or [])
            if label in cmdline:
                print(f"[BLOCKED] Matrix already running in '{universe_id}'.")
                os._exit(1)
        except Exception:
            continue
