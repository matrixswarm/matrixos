import os
import json
import time
import psutil
from pathlib import Path

def list_active_hive(pod_root="pod"):
    print("🧠 LIVE HIVE STATUS")
    print("="*60)

    now = time.time()
    pod_root = Path(pod_root)

    for pod_dir in pod_root.iterdir():
        boot_file = pod_dir / "boot.json"
        if not boot_file.exists():
            continue

        try:
            with open(boot_file, "r", encoding="utf-8") as f:
                boot_data = json.load(f)

            universal_id = boot_data.get("universal_id")
            pid = boot_data.get("pid")
            cmdline = boot_data.get("cmd", [])
            boot_time = boot_data.get("boot_time", 0)

            if not universal_id or not pid or not cmdline:
                continue

            alive = False
            for proc in psutil.process_iter(['pid', 'cmdline', 'create_time']):
                try:
                    if proc.info['pid'] == pid and proc.info['cmdline'] == cmdline:
                        alive = True
                        uptime = now - proc.info['create_time']
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if alive:
                print(f"🔵 Agent: {universal_id}")
                print(f"   PID: {pid}")
                print(f"   CMD: {' '.join(cmdline)}")
                print(f"   Uptime: {int(uptime)} seconds ({uptime/60:.2f} minutes)")
                print("-"*60)

        except Exception as e:
            print(f"[ERROR] Failed reading pod {pod_dir.name}: {e}")

    print("="*60)
    print("✅ Hive Scan Complete.")

if __name__ == "__main__":
    list_active_hive()
