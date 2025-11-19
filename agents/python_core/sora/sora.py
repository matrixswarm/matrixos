# Authored by Daniel F MacDonald and ChatGPT 5.1 aka The Generals

# MatrixSwarm SORA Agent
# Oracle-Inspired Architecture — Video Generation + Job Tracking

import sys, os, time, json, uuid, threading, shutil
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from openai import OpenAI
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):

    def __init__(self):
        super().__init__()

        try:
            self.AGENT_VERSION = "1.0.0"

            cfg = self.tree_node.get("config", {})

            # ---------------------------------------------------
            # OpenAI API Config (Injected via Connection Manager)
            # ---------------------------------------------------
            self.api_key = cfg.get("api_key")
            self.model = cfg.get("model", "gpt-sora-1")
            self.resolution = cfg.get("resolution", "1920x1080")
            self.poll_interval = int(cfg.get("poll_interval", 4))

            self._cfg_lock = threading.Lock()
            self.client = OpenAI(api_key=self.api_key)

            # ---------------------------------------------------
            # STATIC COMM STORAGE (Oracle-inspired mailbox style)
            # ---------------------------------------------------
            self.sora_root = os.path.join(
                self.path_resolution["static_comm_path_resolved"],
                "sora"
            )
            os.makedirs(self.sora_root, exist_ok=True)

            self.jobs_dir = os.path.join(self.sora_root, "jobs")
            self.outbox_dir = os.path.join(self.sora_root, "outbox")

            os.makedirs(self.jobs_dir, exist_ok=True)
            os.makedirs(self.outbox_dir, exist_ok=True)

            self._last_config = {}
            self._emit_beacon = self.check_for_thread_poke(
                "worker", timeout=self.poll_interval * 2, emit_to_file_interval=10
            )

        except Exception as e:
            self.log("[SORA][INIT][ERROR]", error=e)

    # -----------------------------------------------------------
    # Utility Helpers
    # -----------------------------------------------------------
    def _job_path(self, uid):
        return os.path.join(self.jobs_dir, uid)

    def _load_json(self, path, default=None):
        try:
            if os.path.exists(path):
                return json.load(open(path))
        except:
            pass
        return default

    def _save_json(self, path, data):
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception as e:
            self.log("[SORA][SAVE][ERROR]", error=e)

    # -----------------------------------------------------------
    # COMMAND HANDLER — NEW SORA PROMPT
    # -----------------------------------------------------------
    def cmd_sora_prompt(self, content, packet, identity: IdentityObject = None):
        """
        Accept new Sora video job request. Similar to Oracle cmd handler.
        """
        try:
            prompt_text = content.get("prompt", "")
            params = content.get("params", {})
            session_id = content.get("session_id")
            return_handler = content.get("return_handler", "sora.job.received")

            if not prompt_text:
                self.log("[SORA][PROMPT][ERROR] Empty prompt.")
                return

            job_id = uuid.uuid4().hex
            job_dir = self._job_path(job_id)
            os.makedirs(job_dir, exist_ok=True)

            # Save metadata
            self._save_json(os.path.join(job_dir, "prompt.json"), {
                "prompt": prompt_text,
                "params": params,
                "timestamp": int(time.time())
            })

            self._save_json(os.path.join(job_dir, "state.json"), {
                "status": "queued",
                "progress": 0,
                "openai_job_id": None
            })

            # Reflex reply like Oracle
            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": return_handler,
                "content": {
                    "job_id": job_id,
                    "status": "queued",
                    "session_id": session_id
                }
            })
            self.pass_packet(pk, packet.get("origin", "matrix"))

            self.log(f"[SORA] Job queued → {job_id}")

        except Exception as e:
            self.log("[SORA][PROMPT][EXCEPTION]", error=e)

    # -----------------------------------------------------------
    # WORKER LOOP (Oracle style)
    # -----------------------------------------------------------
    def worker(self, config=None, identity=None):

        if self.running:
            self._emit_beacon()

            # Live config updates, Oracle style
            if isinstance(config, dict) and config != self._last_config:
                self._apply_live_config(config)
                self._last_config = dict(config)

            # Process jobs
            try:
                for job_id in os.listdir(self.jobs_dir):
                    job_dir = self._job_path(job_id)
                    state = self._load_json(os.path.join(job_dir, "state.json"), {})

                    if not state:
                        continue

                    match state.get("status"):
                        case "queued":
                            self._start_job(job_id, job_dir, state)

                        case "pending_openai":
                            self._poll_job(job_id, job_dir, state)

            except Exception as e:
                self.log("[SORA][WORKER][ERROR]", error=e)

            interruptible_sleep(self, self.poll_interval)
            return

        # Shutdown
        self.log("[SORA] Shutdown requested.")
        interruptible_sleep(self, 0.5)

    # -----------------------------------------------------------
    # LIVE CONFIG UPDATE (Oracle-style hot reload)
    # -----------------------------------------------------------
    def _apply_live_config(self, cfg: dict):
        try:
            new_key = cfg.get("api_key", self.api_key)
            new_model = cfg.get("model", self.model)
            new_res = cfg.get("resolution", self.resolution)

            with self._cfg_lock:
                if new_key != self.api_key:
                    self.api_key = new_key
                    self.client = OpenAI(api_key=new_key)
                    self.log("[SORA] API key updated.")

                if new_model != self.model:
                    self.model = new_model
                    self.log(f"[SORA] Model set → {new_model}")

                if new_res != self.resolution:
                    self.resolution = new_res
                    self.log(f"[SORA] Resolution set → {new_res}")

        except Exception as e:
            self.log("[SORA][CONFIG][ERROR]", error=e)

    # -----------------------------------------------------------
    # JOB START — Submit generation request
    # -----------------------------------------------------------
    def _start_job(self, job_id, job_dir, state):
        try:
            prompt_data = self._load_json(os.path.join(job_dir, "prompt.json"))

            with self._cfg_lock:
                client = self.client
                model = self.model
                resolution = self.resolution

            prompt = prompt_data.get("prompt")

            # === SUBMIT GENERATION JOB TO OPENAI SORA ===
            resp = client.videos.generate(
                model=model,
                prompt=prompt,
                size=resolution
            )

            openai_job_id = resp.id

            state["status"] = "pending_openai"
            state["openai_job_id"] = openai_job_id
            state["progress"] = 0
            self._save_json(os.path.join(job_dir, "state.json"), state)

            self.log(f"[SORA] Submitted job {job_id} → OpenAI: {openai_job_id}")

        except Exception as e:
            self.log("[SORA][SUBMIT][ERROR]", error=e)
            state["status"] = "error"
            state["error"] = "submit_failed"
            self._save_json(os.path.join(job_dir, "state.json"), state)

    # -----------------------------------------------------------
    # JOB POLLING — Fetch status + download video
    # -----------------------------------------------------------
    def _poll_job(self, job_id, job_dir, state):
        try:
            openai_id = state.get("openai_job_id")
            if not openai_id:
                return

            with self._cfg_lock:
                client = self.client

            # Poll job status
            status_resp = client.videos.status(openai_id)

            if status_resp.state == "completed":
                # === DOWNLOAD FINAL VIDEO ===
                file_bytes = client.videos.get(openai_id)

                out_dir = os.path.join(job_dir, "out")
                os.makedirs(out_dir, exist_ok=True)

                out_path = os.path.join(out_dir, "final.mp4")
                with open(out_path, "wb") as f:
                    f.write(file_bytes)

                # Finalize state
                state["status"] = "done"
                state["end_ts"] = int(time.time())
                state["output_file"] = "final.mp4"
                self._save_json(os.path.join(job_dir, "state.json"), state)

                # COPY TO OUTBOX for rsync_boy
                shutil.copy2(out_path, os.path.join(self.outbox_dir, f"{job_id}.mp4"))

                self.log(f"SORA video finished → {job_id}")
                self.log(f"[SORA] Job complete: {job_id}")

            elif status_resp.state == "failed":
                state["status"] = "error"
                state["error"] = "generation_failed"
                self._save_json(os.path.join(job_dir, "state.json"), state)
                self.log(f"SORA job FAILED → {job_id}")

            else:
                # Still running
                state["progress"] = status_resp.progress
                self._save_json(os.path.join(job_dir, "state.json"), state)

        except Exception as e:
            self.log("[SORA][POLL][ERROR]", error=e)
            state["status"] = "error"
            state["error"] = "poll_failed"
            self._save_json(os.path.join(job_dir, "state.json"), state)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
