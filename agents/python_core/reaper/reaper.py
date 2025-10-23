# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# ╔═══════════════════════════════════════════════╗
# ║              ☠ REAPER AGENT ☠                ║
# ║  Tactical Cleanup · Restart · Wipe Authority ║
# ║                v3.0 Rebuild                  ║
# ╚═══════════════════════════════════════════════╝
import sys, os, time, json, shutil, psutil
from pathlib import Path
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    """
    Command-driven **Reaper** agent.

    Listens for takedown / restart orders from Matrix, executes the
    necessary OS-level actions (drop a “die” cookie, SIGTERM / SIGKILL,
    pod-folder cleanup, etc.), and then reports progress back through
    `cmd_reap_status`.
    """

    def __init__(self):
        """
        Boot strap.

        * Calls parent `BootAgent.__init__` to wire logging, path
          resolution, and CLI parsing.
        * Spins up a thread-poke beacon so Matrix can confirm Reaper is
          responsive (`self._emit_beacon` holds the stop-event handle).
        """
        super().__init__()
        self._emit_beacon = self.check_for_thread_poke("reaper", timeout=30, emit_to_file_interval=10)

    # ---------------------------------------------------------
    # CORE ENTRY
    # ---------------------------------------------------------
    def cmd_reap_agents(self, content, packet, identity=None):
        """
        Matrix entry-point: execute a batch of Reaper targets.

        Args:
            content: Dict with a `targets` list; each target follows::

                    {
                        "universal_id": "<uid>",
                        "op_stage": "delete_start" | "restart_wait" | …
                        ...optional hints like "pid", "pod_path"...
                    }

            packet: Transport envelope (unused beyond logging).
            identity: Caller’s identity; must be signed by Matrix.

        Flow:
            * Verifies identity belongs to the Matrix core.
            * De-duplicates repeated `(uid, op_stage)` pairs in the same
              batch.
            * Routes each target to the matching `_handle_*` stage
              helper.
            * Any exception in an individual helper is caught and
              reported to Matrix via `_report_to_matrix`.

        Side-Effects:
            May kill PIDs, drop files, or wipe directories on disk.

        Returns:
            None – orchestration only.
        """
        try:

            if not self.verify_identity(identity, ['matrix']):
                return

            targets = content.get("targets", [])
            seen = set()
            for t in targets:
                uid = t.get("universal_id")
                if not uid:
                    self.log("[REAPER] Skipping target with no universal_id")
                    continue  # prevents 'Missing or unknown universal_id.'
                stage = t.get("op_stage")

                # optional: de-dup same uid in same batch
                key = (uid, stage)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    if stage == "shutdown_probe":
                        self._handle_shutdown_probe(content)
                    elif stage == "delete_start":
                        self._handle_delete_start(t)
                    elif stage == "delete_escalate":
                        self._handle_delete_escalate(t)
                    elif stage == "delete_cleanup":
                        self._handle_delete_cleanup(t)
                    elif stage == "restart_start":
                        self._handle_restart_start(t)
                    elif stage == "restart_wait":
                        self._handle_restart_wait(t)
                    elif stage == "restart_escalate":
                        self._handle_restart_escalate(t)
                    elif stage == "restart_cleanup":
                        self._handle_restart_cleanup(t)
                    else:
                        self._report_to_matrix(uid, stage, success=False, error=f"Unknown stage '{stage}'")
                except Exception as e:
                    self._report_to_matrix(uid, stage, success=False, error=str(e))
        except Exception as e:
            self.log(error=e, block="main_try")

    def _handle_shutdown_probe(self, content):
        """
        Stage: **shutdown_probe**

        Ping each target and report whether its PID is alive, dead, or
        the pod folder is already missing.

        Args:
            content: Same structure passed from `cmd_reap_agents`.

        Returns:
            None – emits one `_report_to_matrix` call per target.
        """
        try:
            for t in content.get("targets", []):
                uid = t.get("universal_id")
                pid, pod_path = self._resolve_runtime_info(uid)

                # Case 1: pod or pid found → safe
                if pod_path or pid:
                    try:
                        state = "alive" if pid and self.is_pid_alive(pid) else "dead"
                    except psutil.AccessDenied:
                        state = "alive"  # can't inspect but it's real
                    self._report_to_matrix(
                        uid,
                        stage="shutdown_probe",
                        success=True,
                        error=None,
                        extra={"pid": pid, "pod_path": pod_path, "state": state}
                    )
                    continue

                # Case 2: nothing verifiable — assume safe if prior restart wiped the pod
                if not pid and not pod_path:
                    state = "already_dead"
                    self._report_to_matrix(
                        uid,
                        stage="shutdown_probe",
                        success=True,
                        error=None,
                        extra={"pid": None, "pod_path": None, "state": state}
                    )
                    self.log(f"[REAPER] {uid} pod missing, assuming already dead (safe delete).")
                    return


            self.log(f"[PROBE] shutdown_probe complete: {len(content['targets'])} targets dispatched.")

        except Exception as e:
            self.log(error=e, block="main_try")

    # ---------------------------------------------------------
    # SUPPORT
    # ---------------------------------------------------------
    def is_pid_alive(self, pid: int) -> bool:
        """
        Safer PID-liveness check wrapped around `psutil`.

        * Logs status for audit.
        * Treats `AccessDenied` and unexpected errors as “alive” so
          escalation logic errs on the side of caution.

        Args:
            pid: OS process ID.

        Returns:
            True if the process is running and not zombie/dead.
        """
        try:
            proc = psutil.Process(pid)
            status = proc.status()
            alive = proc.is_running() and status not in (
                psutil.STATUS_DEAD, psutil.STATUS_ZOMBIE
            )
            self.log(f"[REAPER][PID] {pid} status={status} alive={alive}")
            return alive
        except psutil.NoSuchProcess:
            self.log(f"[REAPER][PID] {pid} not found (NoSuchProcess)")
            return False
        except psutil.ZombieProcess:
            self.log(f"[REAPER][PID] {pid} zombie — treat as dead")
            return False
        except psutil.AccessDenied:
            # If we can't inspect it, assume it's still alive so escalation triggers
            self.log(f"[REAPER][PID] {pid} access denied — treating as alive for safety")
            return True
        except Exception as e:
            self.log(f"[REAPER][PID] {pid} unexpected error: {e} — treating as alive")
            return True

    def _handle_restart_start(self, target):
        """
        Stage 1 of restart: verify the process is down and clear pod.

        Drops a die-file if the process is still running, otherwise
        cleans residual pod files so Matrix can spawn a fresh instance.

        Args:
            target: Target dict from `cmd_reap_agents`.
        """
        uid = target["universal_id"]
        pid = target.get("pid")
        pod_path = target.get("pod_path")

        if not pid or not pod_path:
            pid, pod_path = self._resolve_runtime_info(uid)
            if pid:
                target["pid"] = pid
            if pod_path:
                target["pod_path"] = pod_path

        try:
            if not pid:
                self._cleanup_paths(uid, target, full=False)
                self._report_to_matrix(
                    uid,
                    stage="restart_start",
                    success=True,
                    extra={"state": "pod_cleared", "pid": pid, "pod_path": pod_path}
                )
                self.log(f"[REAPER] {uid} no PID found, assuming already shut down.")
                return

            if not pid or pid <= 0:
                raise RuntimeError("Missing or invalid PID")

            alive = None
            try:
                alive = self.is_pid_alive(pid)
            except Exception as e:
                raise RuntimeError(f"PID verification failed: {e}")

            if alive:
                self._drop_die(uid)
                self._report_to_matrix(uid, "restart_start",
                                       success=True,
                                       extra={"state": "alive", "pid": pid, "pod_path": pod_path})
                return

            self._cleanup_paths(uid, target, full=False)
            die = os.path.join(self.path_resolution["comm_path"], uid, "incoming", "die")
            if os.path.exists(die):
                os.remove(die)
            self._report_to_matrix(uid, "restart_start",
                                   success=True,
                                   extra={"state": "pod_cleared", "pid": pid, "pod_path": pod_path})
        except Exception as e:
            self._report_to_matrix(uid, "restart_start",
                                   success=False, error=str(e))

    def _handle_restart_wait(self, target):
        """
        Stage 2 of restart: wait-loop check.

        Re-checks PID; reports “alive” or “pod_cleared” so Matrix knows
        whether to escalate or proceed to cleanup.
        """
        uid = target["universal_id"]
        pid = target.get("pid")
        if not pid:
            pid, _ = self._resolve_runtime_info(uid)

        try:
            if not pid or not self.is_pid_alive(pid):
                self._report_to_matrix(uid, "restart_wait",
                                       success=True,
                                       extra={"state": "pod_cleared", "pid": pid})
            else:
                self._report_to_matrix(uid, "restart_wait",
                                       success=True,
                                       extra={"state": "alive", "pid": pid})
        except Exception as e:
            self._report_to_matrix(uid, "restart_wait", success=False, error=str(e))

    def _handle_restart_escalate(self, target):
        """
        Stage 3 of restart: forced kill.

        Sends SIGTERM → short sleep → SIGKILL if the process won’t die.
        """
        uid = target["universal_id"]
        pid = target.get("pid")
        if not pid:
            pid, _ = self._resolve_runtime_info(uid)

        try:
            if pid and self.is_pid_alive(pid):
                os.kill(pid, 15)
                time.sleep(2)
                if self.is_pid_alive(pid):
                    os.kill(pid, 9)
                    time.sleep(1)

            if not self.is_pid_alive(pid):
                self._report_to_matrix(uid, "restart_escalate",
                                       success=True,
                                       extra={"state": "terminated"})
            else:
                raise RuntimeError("Process still alive after escalation kill.")
        except Exception as e:
            self._report_to_matrix(uid, "restart_escalate", success=False, error=str(e))

    def _handle_restart_cleanup(self, target):
        """
        Final stage of restart: clear pod + die cookie and confirm clean.
        """
        uid = target["universal_id"]
        pid, pod_path = self._resolve_runtime_info(uid)
        try:
            self._cleanup_paths(uid, {"pod_path": pod_path, "comm_path": self.path_resolution["comm_path"]}, full=False)
            # remove lingering die cookie
            die = os.path.join(self.path_resolution["comm_path"], uid, "incoming", "die")
            if os.path.exists(die):
                os.remove(die)
            self._report_to_matrix(uid, "restart_cleanup", success=True, extra={"state": "cleaned"})
        except Exception as e:
            self._report_to_matrix(uid, "restart_cleanup", success=False, error=str(e))

    def _report_to_matrix(self, uid, stage, success, error=None, extra=None):
        """
        Wrap → sign → ship a `cmd_reap_status` packet back to Matrix.

        Args:
            uid: Agent UID the report applies to.
            stage: Lifecycle stage we just handled.
            success: Boolean flag.
            error: Optional error string.
            extra: Arbitrary dict merged into `result`.

        Silent-fails if packet creation or dispatch bombs.
        """
        if not uid:
            self.log(f"[REAPER][REPORT] Missing universal_id for stage '{stage}' — skipping report")
            return

        try:
            payload = {
                "handler": "cmd_reap_status",
                "content": {
                    "universal_id": uid,
                    "stage": stage,
                    "result": {
                        "success": success,
                        "error": error,
                        **(extra or {})
                    },
                },
                "timestamp": time.time(),
                "origin": self.command_line_args.get("universal_id", "reaper"),
            }

            self.log(
                f"[REAPER][REPORT] ➤ Reporting to Matrix: uid={uid}, stage={stage}, success={success}, error={error}")
            self.log(f"[REAPER][REPORT] ➤ Payload: {json.dumps(payload, indent=2)}")

            pk = self.get_delivery_packet("standard.command.packet")
            if not pk:
                raise RuntimeError("Failed to create delivery packet.")

            pk.set_data(payload)
            self.pass_packet(pk, "matrix")

        except Exception as e:
            self.log(f"[REAPER][ERROR] Failed to report to Matrix (stage: {stage}, uid: {uid}): {e}",
                     block="_report_to_matrix")

    # ---------------------------------------------------------
    # STAGE HANDLERS
    # ---------------------------------------------------------
    def _handle_delete_start(self, target):
        """
        Stage 1 of delete: attempt graceful shutdown via die-file or
        proceed directly if already dead.
        """
        uid = target["universal_id"]
        pid = target.get("pid")
        if not pid:
            pid, recovered_pod = self._resolve_runtime_info(uid)
            if recovered_pod:
                target["pod_path"] = recovered_pod
        try:
            # Step 1: verify PID legitimacy
            if not pid or pid <= 0:
                raise RuntimeError("Missing or invalid PID")

            alive = None
            try:
                alive = self.is_pid_alive(pid)
            except Exception as e:
                raise RuntimeError(f"PID verification failed: {e}")

            if alive:
                # alive → drop die cookie, report back and exit
                self._drop_die(uid)
                self._report_to_matrix(uid, "delete_start",
                                       success=True,
                                       extra={"state": "alive"})
            else:
                self._report_to_matrix(uid, "delete_start",
                                       success=True,
                                       extra={"state": "dead"})
        except Exception as e:
            self._report_to_matrix(uid, "delete_start",
                                   success=False, error=str(e))

    def _handle_delete_escalate(self, target):
        """
        Stage 2 of delete: forced termination after timeout.
        """
        uid = target["universal_id"]

        # always refresh runtime info; don't trust incoming fields
        fresh_pid, fresh_pod = self._resolve_runtime_info(uid)
        if fresh_pod:
            target["pod_path"] = fresh_pod
        if fresh_pid:
            target["pid"] = fresh_pid

        pid = target.get("pid")

        try:
            if pid and self.is_pid_alive(pid):
                self.log(f"[REAPER] ⚠️ Escalating kill for {uid} (pid={pid})")
                os.kill(pid, 15)
                time.sleep(2)
                if self.is_pid_alive(pid):
                    os.kill(pid, 9)
                    self.log(f"[REAPER] 💀 Sent SIGKILL to {uid} (pid={pid})")
                    time.sleep(1)

            # post-kill confirmation (re-resolve again in case a supervisor respawned)
            confirm_pid, _ = self._resolve_runtime_info(uid)
            if not confirm_pid or not self.is_pid_alive(confirm_pid):
                self._report_to_matrix(uid, "delete_escalate",
                                       success=True, extra={"state": "terminated"})
            else:
                raise RuntimeError(f"{uid} still alive after escalation kill (pid={confirm_pid}).")

        except Exception as e:
            self._report_to_matrix(uid, "delete_escalate", success=False, error=str(e))


    # ---------------------------------------------------------
    # UTILITIES
    # ---------------------------------------------------------
    def _drop_die(self, uid):
        """
        Touch an `incoming/die` file in the agent’s comm folder – the
        agent’s watchdog should pick this up and shut down gracefully.
        """
        try:
            incoming = os.path.join(
                self.path_resolution["comm_path"], uid, "incoming"
            )
            os.makedirs(incoming, exist_ok=True)
            with open(os.path.join(incoming, "die"), "w", encoding="utf-8") as f:
                f.write("true")
                f.close()
            self.log(f"[REAPER] Dropped die cookie for {uid}")
        except Exception as e:
            raise RuntimeError(f"Failed to drop die cookie for {uid}: {e}")

    def _handle_delete_cleanup(self, target):
        """
        Final delete stage: nuke pod directory *and* comm folder.

        Ensures idempotency—will try to kill lingering PIDs one last
        time, but carries on even if they’re already gone.
        """
        uid = target["universal_id"]

        # Always re-derive; packet fields are hints only
        _, live_pod = self._resolve_runtime_info(uid)
        pod_path = live_pod or target.get("pod_path")  # prefer live

        comm_path = self.path_resolution.get("comm_path")

        # Idempotent: best-effort kill just in case the process lingered
        pid = target.get("pid")
        if pid and self.is_pid_alive(pid):
            self.log(f"[REAPER] ⚠️ {uid} still alive in cleanup (pid={pid}) — forcing final kill.")
            try:
                os.kill(pid, 15)
                time.sleep(1.5)
                if self.is_pid_alive(pid):
                    os.kill(pid, 9)
                    self.log(f"[REAPER] 💀 Forced SIGKILL on {uid} (pid={pid})")
            except Exception as e:
                self.log(f"[REAPER][WARN] Final kill attempt failed for {uid}: {e}")

        try:
            # Delete pod if present
            self._cleanup_agent_footprint(uid, pod_path=pod_path, comm_path=comm_path, nuke_comm=True)
            self._report_to_matrix(uid, "delete_cleanup", success=True, extra={"state": "cleaned"})
        except Exception as e:
            self._report_to_matrix(uid, "delete_cleanup", success=False, error=str(e))

    def _cleanup_paths(self, uid, target, full=True):
        """
        Thin wrapper that passes pod/comm paths into the generic
        `_cleanup_agent_footprint`.

        Args:
            uid: Agent UID.
            target: Dict possibly holding `pod_path`, `comm_path`.
            full: If True, also purge the entire comm folder.
        """
        pod_path = target.get("pod_path")
        comm_path = target.get("comm_path")
        self._cleanup_agent_footprint(uid, pod_path=pod_path, comm_path=comm_path, nuke_comm=full)

    def _cleanup_agent_footprint(self, uid, pod_path=None, comm_path=None, *, nuke_comm=False):
        """
        Recursively delete pod and/or comm directories within the
        approved roots, guarding against path-traversal.

        Args:
            uid: Agent UID (for logging only).
            pod_path: Absolute path to the pod directory.
            comm_path: Root comm directory (`.../<uid>` is appended).
            nuke_comm: If True, remove `comm_path/uid` as well.
        """
        try:
            base_pod_root = Path(self.path_resolution.get("pod_path", "")).resolve()
            base_comm_root = Path(self.path_resolution.get("comm_path", "")).resolve()
            self.log(
                f"[REAPER][DEBUG] base_pod_root={base_pod_root} base_comm_root={base_comm_root} pod_path_arg={pod_path}")

            # Pod
            if pod_path:
                podp = Path(pod_path)
                try:
                    podp.relative_to(base_pod_root)
                    if podp.is_dir():
                        shutil.rmtree(podp, ignore_errors=True)
                        self.log(f"[REAPER] 🧹 Cleared pod {podp}")
                    else:
                        self.log(f"[REAPER] (pod already gone) {podp}")
                except ValueError:
                    self.log(f"[REAPER][WARN] pod outside pod_root; refusing: {podp}")

            # Comm
            if nuke_comm and comm_path:
                comp = Path(comm_path).resolve() / uid
                try:
                    comp.relative_to(base_comm_root)
                    if comp.is_dir():
                        shutil.rmtree(comp, ignore_errors=True)
                        self.log(f"[REAPER] 🧹 Cleared comm {comp}")
                    else:
                        self.log(f"[REAPER] (comm already gone) {comp}")
                except ValueError:
                    self.log(f"[REAPER][WARN] comm outside comm_root; refusing: {comp}")

        except Exception as e:
            self.log(error=e, block="_cleanup_agent_footprint", level="ERROR")

    def _resolve_runtime_info(self, uid):
        """
        Best-effort lookup of an agent’s live PID and pod folder.

        Search order:
            1. Active process list (`--job <universe>:<uid>` in cmdline)
            2. `boot.json` files under the pod root
            3. Newest spawn record in `comm/<uid>/spawn/`

        Returns:
            (pid, pod_path) – either may be `None` if not found.
        """
        universe = self.command_line_args.get("universe")
        pod_root = Path(self.path_resolution.get("pod_path", ""))
        comm_root = Path(self.path_resolution.get("comm_path", ""))

        # --- Live process table ---
        try:
            for proc in psutil.process_iter(attrs=["pid", "cmdline"]):
                cmd = proc.info.get("cmdline")
                if not cmd:
                    continue
                joined = " ".join(cmd)
                if f"--job {universe}:{uid}" not in joined:
                    continue

                for arg in cmd:
                    if "/pod/" in arg:
                        pod_uuid = arg.split("/pod/")[-1].split("/")[0]
                        pod_path = pod_root / pod_uuid
                        if pod_path.exists():
                            self.log(f"[REAPER] Live pod detected for {uid}: {pod_path}")
                            return proc.info["pid"], str(pod_path)
                # fallback to last arg heuristic
                run_path = Path(cmd[-1]) if len(cmd) else None
                if run_path and run_path.parent.exists():
                    return proc.info["pid"], str(run_path.parent)
        except Exception as e:
            self.log(f"[REAPER] Live scan failed: {e}")

        # --- boot.json fallback ---
        try:
            for boot_file in pod_root.glob("*/boot.json"):
                try:
                    with open(boot_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data.get("universal_id") == uid:
                        pid = data.get("pid")
                        return pid, str(boot_file.parent)
                except Exception:
                    continue
        except Exception as e:
            self.log(f"[REAPER] Boot.json scan failed: {e}")

        # --- spawn file fallback ---
        try:
            spawn_dir = comm_root / uid / "spawn"
            if spawn_dir.is_dir():
                spawn_files = sorted(
                    [f for f in spawn_dir.glob("*.spawn")],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True
                )
                if spawn_files:
                    latest = spawn_files[0].name
                    pod_uuid = latest.split("_", 1)[-1].replace(".spawn", "")
                    pod_path = pod_root / pod_uuid
                    if pod_path.exists():
                        self.log(f"[REAPER] 🗂 Using spawn record for {uid}: {pod_path}")
                        return None, str(pod_path)
        except Exception as e:
            self.log(f"[REAPER] Spawn record scan failed: {e}")

        return None, None


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
