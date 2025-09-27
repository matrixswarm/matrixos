# Updated B2Bomber — gentler, staggered, heartbeat aware
# drop this over your existing b2_bomber.py (replace class B2Bomber)
import os
import time
import signal
import psutil
import threading
from pathlib import Path
from core.python_core.class_lib.file_system.util.json_safe_write import JsonSafeWrite

class B2Bomber:
    """
    Safer carpet-bombing: drop die cookies, wait per-agent,
    escalate in small batches, use process-groups where possible.
    """

    def __init__(self, logger=None):
        self.agents = {}
        self.logger = logger

    def log_info(self, message):
        if self.logger:
            try:
                self.logger.info(message)
                return
            except Exception:
                pass
        print(message)

    def level_it(self, target_paths, check_interval=2, timeout=30, batch_size=3, dry_run=False):
        """
        target_paths: list of dicts containing at least: {'universal_id', 'comm_path', 'pid'}
        check_interval: seconds between checks while waiting
        timeout: total seconds to allow for graceful shutdown (per-agent)
        batch_size: how many PIDs to escalate at once
        dry_run: if True, don't actually send signals (for testing)
        """
        self.log_info("[CARPET-BOMB][INFO] Initiating universe-wide carpet-bombing...")
        if not target_paths:
            self.log_info("[CARPET-BOMB][WARN] No agents provided.")
            return

        # 0) Normalize
        targets = [t for t in target_paths if t is not None]
        # 1) Drop die cookies (polite)
        self.pass_out_die_cookies(targets, dry_run=dry_run)

        # 2) Wait per-agent for graceful exit
        survivors = self.wait_for_agents_shutdown(targets, check_interval=check_interval, timeout=timeout)

        # 3) If survivors remain, attempt polite termination (proc.terminate or SIGTERM to pg)
        if survivors:
            self.log_info("[CARPET-BOMB][WARNING] Some agents failed to terminate gracefully. Escalating...")
            # staged escalation to avoid thundering herd
            uids = [s.get("universal_id") for s in survivors]
            self.log_info(f"[CARPET-BOMB] Survivors: {uids}")
            self.escalate_shutdown(survivors, batch_size=batch_size, dry_run=dry_run)
        else:
            self.log_info("[CARPET-BOMB][INFO] All agents shut down cleanly.")

        self.log_info("[CARPET-BOMB][INFO] Universe-wide carpet-bombing operation concluded.")

    def pass_out_die_cookies(self, agent_paths, dry_run=False):
        self.log_info("[CARPET-BOMB][INFO] Distributing `die` cookies to agents...")
        for agent in agent_paths:
            try:
                comm_root = agent.get("comm_path")
                uid = agent.get("universal_id")
                if not comm_root or not uid:
                    self.log_info(f"[CARPET-BOMB][SKIP] Missing comm_path/universal_id for agent: {agent}")
                    continue

                uid_dir = os.path.join(comm_root, uid)
                incoming = os.path.join(uid_dir, "incoming")
                os.makedirs(incoming, exist_ok=True)
                die_path = os.path.join(incoming, "die")

                if dry_run:
                    self.log_info(f"[CARPET-BOMB][DRYRUN] Would write die -> {die_path}")
                else:
                    JsonSafeWrite.safe_write(die_path, "terminate")
                    self.log_info(f"[CARPET-BOMB][INFO] `die` cookie distributed for {uid} at {die_path}")

            except Exception as e:
                self.log_info(f"[CARPET-BOMB][ERROR] Failed to distribute `die` cookie for {agent}: {e}")

    def wait_for_agents_shutdown(self, agent_paths, check_interval=2, timeout=30):
        """
        Wait up to `timeout` seconds for each agent to exit.
        Uses per-agent heartbeat (hello.moto) if available to decide quicker.
        Returns list of surviving agent dicts.
        """
        self.log_info("[CARPET-BOMB][INFO] Waiting for agents to ingest die cookie...")

        deadline = time.time() + timeout
        survivors = list(agent_paths)

        # If agent provides comm_path/uid and has hello.moto entries, prefer that for liveness
        def is_alive(agent):
            pid = agent.get("pid")
            if pid and self.is_pid_alive(pid):
                # also check heartbeat dir
                try:
                    comm_root = agent.get("comm_path")
                    uid = agent.get("universal_id")
                    if comm_root and uid:
                        hello_dir = os.path.join(comm_root, uid, "hello.moto")
                        # If directory exists and has any files, treat as alive; else rely on PID
                        if os.path.exists(hello_dir):
                            files = os.listdir(hello_dir)
                            if files:
                                return True
                            # no heartbeat files -> more likely dead or stale
                            return False
                except Exception:
                    return True
                return True
            return False

        while time.time() <= deadline:
            still_alive = []
            for agent in list(survivors):
                if is_alive(agent):
                    still_alive.append(agent)
                    self.log_info(f"[CARPET-BOMB][INFO] Agent {agent.get('universal_id')} (PID {agent.get('pid')}) still breathing...")
                else:
                    self.log_info(f"[CARPET-BOMB][INFO] Agent {agent.get('universal_id')} considered down.")
                    survivors.remove(agent)
            if not still_alive:
                return []  # no survivors
            time.sleep(check_interval)

        # timed out — remaining survivors
        return survivors

    def is_pid_alive(self, pid):
        try:
            if not pid:
                return False
            proc = psutil.Process(pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                return False
            return proc.is_running()
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            self.log_info(f"[CARPET-BOMB][WARN] Access denied checking PID {pid}; assuming alive")
            return True
        except Exception as e:
            self.log_info(f"[CARPET-BOMB][ERROR] Unexpected error checking PID {pid}: {e}")
            return False

    def escalate_shutdown(self, survivors, batch_size=3, grace_after_term=1, dry_run=False):
        """
        survivors: list of agent dicts (with pid/universal_id)
        batch_size: how many to signal concurrently (helps reduce shock)
        grace_after_term: seconds to wait after SIGTERM before SIGKILL
        """
        # group into batches
        batches = [survivors[i:i+batch_size] for i in range(0, len(survivors), batch_size)]
        for idx, batch in enumerate(batches, start=1):
            self.log_info(f"[ESCALATE] Processing batch {idx}/{len(batches)} with {len(batch)} agents...")
            active = {}
            for agent in batch:
                pid = agent.get("pid")
                uid = agent.get("universal_id")
                if not pid:
                    continue
                try:
                    # Try polite terminate first
                    proc = psutil.Process(pid)
                    # If process has a process group, try to signal the whole group (POSIX)
                    try:
                        if os.name == "posix":
                            pgid = os.getpgid(pid)
                            if dry_run:
                                self.log_info(f"[DRYRUN] Would SIGTERM process group {pgid} for {uid}")
                            else:
                                os.killpg(pgid, signal.SIGTERM)
                                self.log_info(f"[CARPET-BOMB] SIGTERM → {uid} (PGID {pgid})")
                        else:
                            if dry_run:
                                self.log_info(f"[DRYRUN] Would terminate PID {pid} for {uid}")
                            else:
                                proc.terminate()
                                self.log_info(f"[CARPET-BOMB] terminate() → {uid} (PID {pid})")
                    except Exception:
                        # Fallback: send SIGTERM to the pid itself
                        if dry_run:
                            self.log_info(f"[DRYRUN] Would SIGTERM PID {pid} for {uid}")
                        else:
                            os.kill(pid, signal.SIGTERM)
                            self.log_info(f"[CARPET-BOMB] SIGTERM → {uid} (PID {pid})")
                    active[uid] = pid
                except psutil.NoSuchProcess:
                    self.log_info(f"[CARPET-BOMB] Already dead: {uid}")
                except Exception as e:
                    self.log_info(f"[CARPET-BOMB] Failed to SIGTERM {uid} (PID {pid}): {e}")

            # give this batch a moment to exit
            time.sleep(grace_after_term)

            # check survivors in this batch and escalate to SIGKILL where needed
            for uid, pid in list(active.items()):
                if self.is_pid_alive(pid):
                    try:
                        if dry_run:
                            self.log_info(f"[DRYRUN] Would SIGKILL PID {pid} for {uid}")
                        else:
                            # Try process group kill first on POSIX, else proc.kill()
                            if os.name == "posix":
                                try:
                                    pgid = os.getpgid(pid)
                                    os.killpg(pgid, signal.SIGKILL)
                                    self.log_info(f"[CARPET-BOMB] SIGKILL → {uid} (PGID {pgid})")
                                except Exception:
                                    os.kill(pid, signal.SIGKILL)
                                    self.log_info(f"[CARPET-BOMB] SIGKILL → {uid} (PID {pid})")
                            else:
                                proc = psutil.Process(pid)
                                proc.kill()
                                self.log_info(f"[CARPET-BOMB] kill() → {uid} (PID {pid})")
                    except Exception as e:
                        self.log_info(f"[CARPET-BOMB] Failed to SIGKILL {uid} (PID {pid}): {e}")

            # short pause before next batch to reduce spike
            time.sleep(0.5)
