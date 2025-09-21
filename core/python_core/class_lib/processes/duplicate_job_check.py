import os
import psutil
from core.python_core.utils.debug.config import DEBUG_CONFIG
from core.python_core.utils.debug.config import DebugConfig

class DuplicateProcessCheck:
    @staticmethod
    def get_job_label(process):
        try:
            cmdline = process.cmdline()
            for idx, arg in enumerate(cmdline):
                if arg == '--job' and idx + 1 < len(cmdline):
                    return cmdline[idx + 1]
                elif arg.startswith('--job='):
                    return arg.split('=', 1)[1]
            return None
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None

    @staticmethod
    def get_self_job_label():
        return DuplicateProcessCheck.get_job_label(psutil.Process(os.getpid()))

    @staticmethod
    def check_duplicate_process(target_label):
        current_pid = os.getpid()
        matches = []

        for proc in psutil.process_iter():
            try:
                if proc.pid == current_pid:
                    continue
                if DuplicateProcessCheck.get_job_label(proc) == target_label:
                    matches.append(proc)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        if not matches:

            debug = DebugConfig()
            if debug.is_enabled():
                print(f"No processes found with the label: {target_label}")
            return False

        all_procs = matches + [psutil.Process(current_pid)]
        earliest = min(all_procs, key=lambda p: (p.create_time(), p.pid))

        if earliest.pid == current_pid:
            print(f"Process {current_pid} with label '{target_label}' is the earliest. Continuing.")
            return False

        print(f"Process {current_pid} is NOT the earliest. Label '{target_label}' claimed by PID {earliest.pid}.")
        return True

    @staticmethod
    def check_duplicate_process_by_path():
        current_pid = os.getpid()
        current_path = psutil.Process(current_pid).cmdline()[1]
        matches = []

        for proc in psutil.process_iter():
            try:
                cmdline = proc.cmdline()
                if proc.pid == current_pid:
                    continue
                if len(cmdline) > 1 and cmdline[1] == current_path:
                    matches.append(proc)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        if not matches:
            print(f"No duplicate processes found for script path: {current_path}")
            return False

        all_procs = matches + [psutil.Process(current_pid)]
        earliest = min(all_procs, key=lambda p: (p.create_time(), p.pid))

        if earliest.pid == current_pid:
            print(f"PID {current_pid} is the earliest for script path. Continuing.")
            return False

        print(f"PID {current_pid} is NOT the earliest. Path claimed by PID {earliest.pid}.")
        return True

    @staticmethod
    def check_all_duplicate_risks(job_label=None, check_path=False):
        """
        Return True if this process should terminate due to either:
        - a duplicate with the same --job label (and this one is newer), OR
        - a duplicate with the same script path (if check_path=True)
        """
        triggered = False

        if job_label:
            if DuplicateProcessCheck.check_duplicate_process(job_label):
                print(f"[DUPLICATE] Process with job label '{job_label}' already running.")
                triggered = True

        if check_path:
            if DuplicateProcessCheck.check_duplicate_process_by_path():
                print("[DUPLICATE] Process with same script path already running.")
                triggered = True

        return triggered