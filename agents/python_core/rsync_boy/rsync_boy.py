# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys, os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))


import time, json
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.processes.thread_launcher import ThreadLauncher
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject


class Agent(BootAgent):
    """
    rsync_boy — Job Dispatcher
    -------------------------
    • Reads declarative job definitions from config
    • Decides when jobs should fire
    • Launches ephemeral factory threads
    • Never performs work itself
    """

    def __init__(self):
        super().__init__()
        self.AGENT_VERSION = "2.0.0"

        cfg = self.tree_node.get("config", {}) or {}

        self.poll_interval = int(cfg.get("poll_interval", 60))
        self.jobs = cfg.get("jobs", [])

        self._last_run = {}  # job_id -> timestamp
        self.thread_launcher = ThreadLauncher(self)

        self._emit_beacon = self.check_for_thread_poke(
            "worker",
            timeout=self.poll_interval * 2,
            emit_to_file_interval=10
        )

        self.log(f"[RSYNC_BOY] Loaded {len(self.jobs)} jobs")

    # --------------------------------------------------
    def _job_due(self, job, now: float) -> bool:
        job_id = job.get("id")
        sched = job.get("schedule", {}) or {}

        interval = int(sched.get("interval_sec", 0))
        run_on_boot = bool(sched.get("run_on_boot", False))

        last = self._last_run.get(job_id)

        if last is None:
            return run_on_boot or interval > 0

        if interval <= 0:
            return False

        return (now - last) >= interval

    # --------------------------------------------------
    def _launch_job(self, job):
        job_id = job["id"]
        factory = job.get("factory")

        if not factory:
            self.log(f"[RSYNC_BOY][WARN] Job {job_id} missing factory")
            return

        # start with job's local config
        cfg = job.get("config", {}).copy()

        # pull top-level mysql/ssh creds into job config
        top_cfg = self.tree_node.get("config", {})
        if "ssh" in top_cfg:
            cfg["ssh"] = top_cfg["ssh"]
            self.log(f"[RSYNC_BOY][_LAUNCH_JOB] Injected SSH creds from top-level config.")
        if "mysql" in top_cfg:
            cfg["mysql"] = top_cfg["mysql"]
            self.log(f"[RSYNC_BOY][_LAUNCH_JOB] Injected MySQL creds from top-level config.")

        self.log(f"[RSYNC_BOY][_LAUNCH_JOB] [DEBUG] final cfg keys: {list(cfg.keys())}")

        context = {"job_id": job_id, "config": cfg}

        self.log(f"[RSYNC_BOY] Launching job '{job_id}' → {factory}")
        self.thread_launcher.launch(
            class_path=f"rsync_boy.factory.{factory}",
            context=context,
            persist=False,
        )

        self._last_run[job_id] = time.time()

    # --------------------------------------------------
    def worker(self, config=None, identity: IdentityObject = None):
        try:
            self._emit_beacon()
            now = time.time()

            # check for config updates
            if isinstance(config, dict) and bool(config.get("push_live_config", 0)):
                self.jobs = config.get("jobs", self.jobs)
                self.poll_interval = int(config.get("poll_interval", self.poll_interval))
                self.log("[RSYNC_BOY] Live config updated")

            for job in self.jobs:
                if not job.get("enabled", False):
                    continue

                if self._job_due(job, now):
                    self._launch_job(job)

        except Exception as e:
            self.log("[RSYNC_BOY][ERROR]", error=e)

        interruptible_sleep(self, self.poll_interval)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()