import os
import json
import time
import psutil
import shutil
from pathlib import Path

def live_hive_watch(pod_root="pod", interval_sec=5):
    try:
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            print("🧠 LIVE HIVE STATUS")
            print("="*80)

            now = time.time()
            pod_root = Path(pod_root)
            agent_count = 0

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
                    uptime = 0
                    for proc in psutil.process_iter(['pid', 'cmdline', 'create_time']):
                        try:
                            if proc.info['pid'] == pid and proc.info['cmdline'] == cmdline:
                                alive = True
                                uptime = now - proc.info['create_time']
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                    if alive:
                        agent_count += 1
                        print(f"🔵 {universal_id.ljust(20)} PID: {str(pid).ljust(7)} Uptime: {int(uptime)}s ({uptime/60:.1f} min)")
                        print(f"   CMD: {' '.join(cmdline)}")
                        print("-"*80)

                except Exception as e:
                    print(f"[ERROR] Failed reading pod {pod_dir.name}: {e}")

            print("="*80)
            print(f"✅ Agents Online: {agent_count}")
            time.sleep(interval_sec)

    except KeyboardInterrupt:
        print("\n[EXIT] Live Hive Watcher terminated by operator.")

if __name__ == "__main__":
    live_hive_watch()
