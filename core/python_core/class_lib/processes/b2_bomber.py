import os
import time
import signal
import psutil
from core.python_core.class_lib.file_system.util.json_safe_write import JsonSafeWrite

class B2Bomber:
    """
    Simple 'level it' bomber:
      - write die cookie
      - wait for graceful exit (timeout)
      - SIGTERM -> short wait -> SIGKILL survivors
    """

    def __init__(self, logger=None, stagger_delay=0.1):
        self.logger = logger
        self.agents = {}
        self.stagger_delay = stagger_delay

    def log_info(self, message):
        if self.logger:
            try:
                # logger may expose .info
                self.logger.info(message)
                return
            except Exception:
                pass
        print(message)

    def pass_out_die_cookies(self, agent_list, dry_run=False):
        """
        agent_list: list of dicts with at least {'universal_id', 'comm_path', 'pod_path', 'pid'}
        Drop die cookie in /comm/{uid}/incoming/die files.
        """
        self.log_info("[B2-BOMBER][UNIVERSE-CARPET-BOMBING-COMMENCING] Distributing `die` cookies.")
        for agent in agent_list:
            try:
                comm_root = agent.get("comm_path")
                uid = agent.get("universal_id")
                pod_path = agent.get("pod_path")

                if not comm_root or not uid:
                    self.log_info(f"[B2-BOMBER][SKIP] Missing comm_path/universal_id for agent: {agent}")
                    continue

                uid_dir = os.path.join(comm_root, uid)
                incoming = os.path.join(uid_dir, "incoming")
                os.makedirs(incoming, exist_ok=True)
                die_path = os.path.join(incoming, "die")

                if dry_run:
                    self.log_info(f"[B2-BOMBER][DRYRUN] Would write die -> {die_path}")
                else:
                    JsonSafeWrite.safe_write(die_path, "terminate")
                    self.log_info(f"B2-BOMBER][DROPPING-DIE-COOKIE] `die` cookie written for {uid} at {die_path}")


                # Track agent info for later escalation
                self.agents[uid] = {
                    "pid": agent.get("pid"),
                    "details": {"cmd": agent.get("details", {}).get("cmd")}
                }

            except Exception as e:
                self.log_info(f"[B2-BOMBER][DROPPING-DIE-COOKIE][ERROR] Failed to distribute die cookie for {agent}: {e}")

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
            self.log_info(f"[B2-BOMBER][IS-ALIVE][WARN] Access denied checking PID {pid}; assuming alive")
            return True
        except Exception as e:
            self.log_info(f"[B2-BOMBER][ERROR] Unexpected error checking PID {pid}: {e}")
            return False

    def wait_for_agents_shutdown(self, check_interval=2, timeout=10):
        """
        Wait up to `timeout` seconds for tracked agents (self.agents) to exit.
        Uses PID + optional hello.moto heartbeat if callers provide comm/uid in details (optional).
        Returns list of surviving agent dict entries (with universal_id and pid).
        """
        self.log_info(f"[B2-BOMBER] Waiting up to {timeout}s for agents to ingest die cookie.")
        deadline = time.time() + timeout
        survivors = []

        # Simplest alive check: pid existence; if you want hello.moto, caller can prefilter
        run=1
        while time.time() <= deadline:
            survivors.clear()
            for uid, info in list(self.agents.items()):
                pid = info.get("pid")
                if pid and self.is_pid_alive(pid):
                    survivors.append({"universal_id": uid, "pid": pid})
                    self.log_info(f"[B2-BOMBER] 💣 Bombing Run {run} Agent {uid} (PID {pid}) still breathing...")
            if not survivors:
                return []
            time.sleep(check_interval)
            run+=1

        # timed out — remaining survivors
        self.log_info(f"[B2-BOMBER] Timeout reached. Survivors: {[s['universal_id'] for s in survivors]}")
        return survivors

    def escalate_shutdown(self, survivors, grace_after_term=1, dry_run=False):
        """
        Immediately attempt polite termination (SIGTERM / proc.terminate), wait `grace_after_term`,
        then SIGKILL any remaining PIDs. No batching — level it.
        """
        if not survivors:
            self.log_info("[B2-BOMBER] No survivors to escalate.")
            return

        # First pass: SIGTERM (prefer process group on POSIX)
        active = {}
        for agent in survivors:
            pid = agent.get("pid")
            uid = agent.get("universal_id")
            if not pid:
                continue
            try:
                proc = psutil.Process(pid)
                try:
                    if os.name == "posix":
                        try:
                            pgid = os.getpgid(pid)
                            if dry_run:
                                self.log_info(f"[DRYRUN] Would SIGTERM process group {pgid} for {uid}")
                            else:
                                os.killpg(pgid, signal.SIGTERM)
                                self.log_info(f"[B2-BOMBER][NUKE] ☢️  SIGTERM → {uid} (PGID {pgid})")
                        except Exception:
                            # fallback to pid
                            if dry_run:
                                self.log_info(f"[DRYRUN] Would SIGTERM PID {pid} for {uid}")
                            else:
                                os.kill(pid, signal.SIGTERM)
                                self.log_info(f"[B2-BOMBER][MIRV] SIGTERM → {uid} (PID {pid})")
                    else:
                        if dry_run:
                            self.log_info(f"[DRYRUN] Would terminate PID {pid} for {uid}")
                        else:
                            proc.terminate()
                            self.log_info(f"[B2-BOMBER] terminate() → {uid} (PID {pid})")
                except Exception as e:
                    self.log_info(f"[B2-BOMBER][WARN] SIGTERM fallback for {uid}: {e}")
                active[uid] = pid
            except psutil.NoSuchProcess:
                self.log_info(f"[B2-BOMBER] Already dead: {uid}")
            except Exception as e:
                self.log_info(f"[B2-BOMBER][ERROR] Failed to SIGTERM {uid} (PID {pid}): {e}")

        # Wait a short grace period
        time.sleep(grace_after_term)

        # Second pass: SIGKILL any remaining
        for uid, pid in list(active.items()):
            if self.is_pid_alive(pid):
                try:
                    if dry_run:
                        self.log_info(f"[DRYRUN] Would SIGKILL PID {pid} for {uid}")
                    else:
                        if os.name == "posix":
                            try:
                                pgid = os.getpgid(pid)
                                os.killpg(pgid, signal.SIGKILL)
                                self.log_info(f"[B2-BOMBER] SIGKILL → {uid} (PGID {pgid})")
                            except Exception:
                                os.kill(pid, signal.SIGKILL)
                                self.log_info(f"[B2-BOMBER] SIGKILL → {uid} (PID {pid})")
                        else:
                            proc = psutil.Process(pid)
                            proc.kill()
                            self.log_info(f"[B2-BOMBER] kill() → {uid} (PID {pid})")
                except Exception as e:
                    self.log_info(f"[B2-BOMBER][ERROR] Failed to SIGKILL {uid} (PID {pid}): {e}")

    def level_it(self, target_list, check_interval=2, timeout=30, dry_run=False):
        """
        Simplified: write die for every target, wait, then level survivors.
        target_list: list of dicts with keys 'universal_id','comm_path','pod_path','pid', 'details'
        """
        self.log_info("[B2-BOMBER] Initiating 'level it' sequence.")
        if not target_list:
            self.log_info("[B2-BOMBER][WARN] No targets provided.")
            return

        # 1) Drop die cookies for each target
        self.pass_out_die_cookies(target_list, dry_run=dry_run)

        # 2) Wait for graceful exit
        survivors = self.wait_for_agents_shutdown(check_interval=check_interval, timeout=timeout)

        # 3) If anybody survived, escalate immediately (no batches)
        if survivors:
            self.log_info("[B2-BOMBER][WARNING] Survivors detected — leveling now.")
            self.escalate_shutdown(survivors, grace_after_term=1, dry_run=dry_run)
        else:
            self.log_info("[B2-BOMBER] All targets exited cleanly.")

        self.log_info("[B2-BOMBER] Universe-wide carpet-bombing operation complete.")
