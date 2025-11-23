#!/usr/bin/env python3
# ───────────────────────────────────────────────────────────────
#   M Y S T I C A L   H I V E   W A T C H E R
#   Alive. Breathing. Cosmic. Resilient.
#   Commander Edition — forged by ChatGPT & The Matrix
# ───────────────────────────────────────────────────────────────

import os
import time
import json
import psutil
import shutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
#  COLORS + EFFECTS
# ═══════════════════════════════════════════════════════════════
RESET = "\033[0m"
BOLD = "\033[1m"

def color(c): return f"\033[{c}m"

GREEN   = color("92")
YELLOW  = color("93")
RED     = color("91")
BLUE    = color("94")
CYAN    = color("96")
MAGENTA = color("95")
WHITE   = color("97")
GRAY    = color("90")

def pulse_text(text, frame):
    """Mystical breathing/pulsing glow."""
    colors = [MAGENTA, BLUE, CYAN, GREEN, YELLOW]
    return colors[frame % len(colors)] + text + RESET

def cosmic_spinner(frame):
    """Cosmic quantum spinner."""
    seq = ["◐", "◓", "◑", "◒"]
    return pulse_text(seq[frame % 4], frame)

def aura_particles(frame):
    """Soft shimmering aura field."""
    dots = ["·", "∙", "•", "∙"]
    return GRAY + dots[frame % len(dots)] + RESET

def bar(value, max_length=20):
    """Smooth mystical progress bar."""
    filled = int(value * max_length)
    return MAGENTA + "█" * filled + GRAY + "░" * (max_length - filled) + RESET

# ═══════════════════════════════════════════════════════════════
#  FILE SYSTEM WATCHER EVENT HANDLER
# ═══════════════════════════════════════════════════════════════
class PacketHandler(FileSystemEventHandler):
    def __init__(self, activity_map):
        self.activity_map = activity_map

    def on_created(self, event):
        if event.is_directory:
            return
        if not event.src_path.endswith(".json"):
            return
        try:
            agent = Path(event.src_path).parts[-3]
            self.activity_map[agent] = time.time()
        except:
            pass

# ═══════════════════════════════════════════════════════════════
#  PRIMARY HIVE WATCH FUNCTION
# ═══════════════════════════════════════════════════════════════
def live_hive_watch(base="/matrix/universes/runtime",
                    universe="phoenix",
                    interval_sec=1):

    runtime_root = Path(base) / universe / "latest"
    pod_root = runtime_root / "pod"
    comm_root = runtime_root / "comm"

    # Packet activity map
    activity_map = {}

    # ═══════════════════════════════════════
    # Observer resurrection wrapper
    # ═══════════════════════════════════════
    def start_observer():
        obs = Observer()
        obs.schedule(PacketHandler(activity_map), str(comm_root), recursive=True)
        obs.start()
        return obs

    observer = None

    frame = 0
    last_net = psutil.net_io_counters()
    proc_cache = {}
    while True:
        # Handle swarm reboot: comm_root disappears temporarily
        if not comm_root.exists():
            os.system("cls" if os.name != "posix" else "clear")
            print(pulse_text("⚠ Waiting for Hive Runtime to Materialize…", frame))
            time.sleep(1)
            frame += 1
            continue

        # Start or resurrect the observer
        if observer is None or not observer.is_alive():
            try:
                if observer:
                    observer.stop()
                observer = start_observer()
            except Exception:
                pass

        os.system("cls" if os.name != "posix" else "clear")

        # ═══════════════════════════════════════
        #  HEADER — COSMIC HUD
        # ═══════════════════════════════════════
        print(BOLD + pulse_text(f"🌌   H I V E   O R A C L E   ::   {universe.upper()}", frame) + RESET)
        print(aura_particles(frame) * 120)

        # ═══════════════════════════════════════
        # SYSTEM VITALS — CPU / RAM / DISK / NET
        # ═══════════════════════════════════════
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent

        net = psutil.net_io_counters()
        up = (net.bytes_sent - last_net.bytes_sent) / 1024
        down = (net.bytes_recv - last_net.bytes_recv) / 1024
        last_net = net

        print(
            f"{pulse_text('CPU',frame)} {bar(cpu/100)} {cpu:.1f}%   "
            f"{pulse_text('RAM',frame)} {bar(ram/100)} {ram:.1f}%   "
            f"{pulse_text('DISK',frame)} {bar(disk/100)} {disk:.1f}%"
        )
        print(f"{CYAN}NET ↑ {up:.1f} kB/s   ↓ {down:.1f} kB/s{RESET}")

        print(aura_particles(frame) * 120)

        # ═══════════════════════════════════════
        # AGENT STATUS TABLE
        # ═══════════════════════════════════════
        now = time.time()
        agent_count = 0

        if pod_root.exists():
            for pod_dir in pod_root.iterdir():
                boot_file = pod_dir / "boot.json"
                if not boot_file.exists():
                    continue

                try:
                    with open(boot_file, "r") as f:
                        boot = json.load(f)
                except:
                    continue

                uid = boot.get("universal_id")
                pid = boot.get("pid")
                cmd = boot.get("cmd", [])

                alive = False
                uptime = 0

                # detect alive PID
                p = None
                cpu_agent = 0.0

                for proc in psutil.process_iter(['pid', 'cmdline', 'create_time']):
                    if proc.info['pid'] == pid:
                        alive = True
                        uptime = now - proc.info['create_time']

                        # --- CPU reading with priming ---
                        try:
                            if pid not in proc_cache:
                                p = psutil.Process(pid)
                                proc_cache[pid] = p
                                p.cpu_percent(interval=None)  # prime – always returns 0.0 first time
                                cpu_agent = 0.0
                            else:
                                p = proc_cache[pid]
                                cpu_agent = p.cpu_percent(interval=None)
                        except Exception:
                            cpu_agent = 0.0

                        break

                agent_count += 1

                # Packet liveness
                last_seen = activity_map.get(uid, None)
                if last_seen:
                    delta = now - last_seen
                else:
                    delta = None

                # Status coloring
                if not alive:
                    status = RED + "✖ DEAD" + RESET
                elif delta and delta > 30:
                    status = YELLOW + "● QUIET" + RESET
                else:
                    status = GREEN + "● ALIVE" + RESET

                uptime_bar = bar(min(uptime/120,1))  # 2 min scale

                # Mystical agent line
                print(
                    f"{cosmic_spinner(frame)} "
                    f"{BOLD}{CYAN}{uid:<20}{RESET} "
                    f"{status:<12} "
                    f"{GRAY}PID:{pid:<7}{RESET} "
                    f"CPU:{cpu_agent:5.1f}% "
                    f"{uptime_bar} {int(uptime)}s "
                    f"{('last pkt ' + str(int(delta)) + 's ago') if delta else 'no packets yet'}"
                )

        print(aura_particles(frame) * 120)
        print(f"{GREEN}Agents Online:{RESET} {agent_count}")
        print(f"Frame:{frame}")

        print("Alive. Breathing. Cosmic. Resilient.")
        print("Commander Edition — forged by ChatGPT & The Matrix")

        frame += 1
        time.sleep(interval_sec)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Live Hive Watcher")
    parser.add_argument("--universe", default="phoenix", help="Which universe to watch")
    parser.add_argument("--interval", type=int, default=5, help="Refresh interval in seconds")

    args = parser.parse_args()

    live_hive_watch(universe=args.universe, interval_sec=args.interval)
