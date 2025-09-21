import os
import time
import json
import psutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class PacketHandler(FileSystemEventHandler):
    def __init__(self, activity_map):
        self.activity_map = activity_map

    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(".json"):
            agent = Path(event.src_path).parts[-3]  # comm/<agent>/incoming/file.json
            self.activity_map[agent] = time.time()

def live_hive_watch(base="/matrix/universes/runtime", universe="phoenix", interval_sec=5):
    runtime_root = Path(base) / universe / "latest"
    pod_root = runtime_root / "pod"
    comm_root = runtime_root / "comm"

    # Track packet activity
    activity_map = {}

    # Watch comm bus
    event_handler = PacketHandler(activity_map)
    observer = Observer()
    observer.schedule(event_handler, str(comm_root), recursive=True)
    observer.start()

    try:
        while True:
            os.system("clear" if os.name == "posix" else "cls")
            print(f"LIVE HIVE STATUS :: {universe.upper()}")
            print("="*80)

            now = time.time()
            agent_count = 0

            for pod_dir in pod_root.iterdir():
                boot_file = pod_dir / "boot.json"
                if not boot_file.exists():
                    continue

                with open(boot_file, "r", encoding="utf-8") as f:
                    boot_data = json.load(f)

                uid = boot_data.get("universal_id")
                pid = boot_data.get("pid")
                cmdline = boot_data.get("cmd", [])

                alive = False
                uptime = 0
                for proc in psutil.process_iter(['pid', 'cmdline', 'create_time']):
                    if proc.info['pid'] == pid and proc.info['cmdline'] == cmdline:
                        alive = True
                        uptime = now - proc.info['create_time']
                        break

                if alive:
                    agent_count += 1
                    last_packet = activity_map.get(uid, 0)
                    since_last = now - last_packet if last_packet else None

                    status = "🟢"
                    if since_last and since_last > 30:
                        status = "🟠"  # warn: stale comm

                    print(f"{status} {uid.ljust(20)} PID:{pid:<6} Uptime:{int(uptime)}s  ", end="")
                    if since_last:
                        print(f"Last packet {int(since_last)}s ago")
                    else:
                        print("No packets yet")

            print("="*80)
            print(f"✅ Agents Online: {agent_count}")
            time.sleep(interval_sec)

    except KeyboardInterrupt:
        observer.stop()
        print("\n[EXIT] Live Hive Watcher terminated.")
    observer.join()

if __name__ == "__main__":
    live_hive_watch()
