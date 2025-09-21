import os
import signal
import time
from pathlib import Path
import psutil

def find_jobs_by_prefix(universe_id, universal_id, match_mode="prefix"):
    """
    Find processes where the --job argument matches a specific value.

    Args:
        universe_id (str): Universe identifier.
        universal_id (str): Agent identifier.
        match_mode (str): "exact" for exact match, "prefix" for startswith match.
                          Defaults to "prefix".
    """
    job_target = f"{universe_id}:{universal_id}"
    matching_processes = []

    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline') or []
            if '--job' in cmdline:
                job_index = cmdline.index('--job') + 1
                if job_index < len(cmdline):
                    job_value = cmdline[job_index]
                    if match_mode == "exact" and job_value == job_target:
                        matching_processes.append(proc.info)
                    elif match_mode == "prefix" and job_value.startswith(job_target):
                        matching_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return matching_processes

def reeeeeeebeeeengaaaaa(match_processes):
    r=""
    try:

        for proc in match_processes:
            pid = proc["pid"]
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception as e:
                r = f"[BOOT][PUNJI][WARN] Could not SIGTERM: {e}"

        # Short wait, then SIGKILL survivors
        time.sleep(2)
        for proc in match_processes:
            pid = proc["pid"]
            if psutil.pid_exists(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                    r = f"[BOOT][PUNJI] SIGKILL → (PID {pid})"
                except Exception as e:
                    r = f"[BOOT][PUNJI][FAIL] Could not SIGKILL → (PID {pid}): {e}"

    except Exception as e:
        r = f"[BOOT][PUNJI][WARN] Could not SIGTERM or PUNJI: {e}"

    return r
