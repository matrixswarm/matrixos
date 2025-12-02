# Authored by Daniel F MacDonald and ChatGPT-5.1 aka The Generals
# Commander Edition — Fully Autonomous SORA Agent (DB + File Hybrid Sync)

import sys, os, time, json, uuid, threading, shutil
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import pymysql
from openai import OpenAI
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject


class Agent(BootAgent):

    def __init__(self):
        super().__init__()
        try:
            self.AGENT_VERSION = "1.1.0"
            cfg = self.tree_node.get("config", {})

            # === OpenAI Config ===
            self.api_key = cfg.get("api_key")
            self.model = cfg.get("model", "gpt-sora-1")
            self.resolution = cfg.get("resolution", "1920x1080")
            self.poll_interval = int(cfg.get("poll_interval", 60))

            self._cfg_lock = threading.Lock()
            self.client = OpenAI(api_key=self.api_key)

            # === MariaDB Config ===
            db_cfg = cfg.get("mysql", {})
            self.db_host = db_cfg.get("host", "localhost")
            self.db_user = db_cfg.get("username", "root")
            self.db_pass = db_cfg.get("password", "")
            self.db_name = db_cfg.get("database", "matrix_pipeline")
            self.db_port = int(db_cfg.get("port", 3306))

            self._db = None
            self.db_enabled = False
            self._connect_db()

            # === File Structure ===
            self.sora_root = os.path.join(self.path_resolution["static_comm_path_resolved"], "sora")
            self.jobs_dir = os.path.join(self.sora_root, "jobs")
            self.outbox_dir = os.path.join(self.sora_root, "outbox")
            os.makedirs(self.jobs_dir, exist_ok=True)
            os.makedirs(self.outbox_dir, exist_ok=True)

            # === Heartbeat ===
            self._emit_beacon = self.check_for_thread_poke("worker", timeout=self.poll_interval * 2, emit_to_file_interval=10)

        except Exception as e:
            self.log("[SORA][INIT][ERROR]", error=e)

    # ------------------------------------------------------------
    # DATABASE HELPERS
    # ------------------------------------------------------------
    def _connect_db(self):
        """Initialize MariaDB connection."""
        try:
            self._db = pymysql.connect(
                host=self.db_host,
                user=self.db_user,
                password=self.db_pass,
                database=self.db_name,
                port=self.db_port,
                autocommit=True
            )
            self.db_enabled = True
            self.log("[SORA][DB] ✅ Connected to MariaDB.")
        except Exception as e:
            self.db_enabled = False
            self.log("[SORA][DB][ERROR] Connection failed.", error=e)

    def _db_run(self, sql, params=None):
        """Execute a SQL query safely with auto-reconnect."""
        if not self.db_enabled:
            self._connect_db()
            if not self.db_enabled:
                return None

        try:
            with self._db.cursor() as cur:
                cur.execute(sql, params or ())
                if sql.strip().lower().startswith(("insert", "update", "delete")):
                    self._db.commit()
                try:
                    return cur.fetchall()
                except Exception:
                    return True
        except Exception as e:
            self.log("[SORA][DB][RUN][ERROR]", error=e)
            self.db_enabled = False
            return None

    # ------------------------------------------------------------
    # JSON UTILS
    # ------------------------------------------------------------
    def _job_path(self, uid): return os.path.join(self.jobs_dir, uid)

    def _load_json(self, path, default=None):
        try:
            if os.path.exists(path):
                return json.load(open(path))
        except Exception:
            pass
        return default

    def _save_json(self, path, data):
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, indent=2)
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception as e:
            self.log("[SORA][SAVE][ERROR]", error=e)

    # ------------------------------------------------------------
    # COMMAND HANDLER — NEW JOB REQUEST
    # ------------------------------------------------------------
    def cmd_sora_prompt(self, content, packet, identity: IdentityObject = None):
        """Accept a new Sora video generation request."""
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

            # Local JSON record
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

            # DB entry
            sql = """
            INSERT INTO sora_jobs (prompt, status, openai_job_id, progress)
            VALUES (%s, 'queued', %s, %s)
            """
            self._db_run(sql, (prompt_text, job_id, 0))

            # Reflex reply
            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": return_handler,
                "content": {"job_id": job_id, "status": "queued", "session_id": session_id}
            })
            self.pass_packet(pk, packet.get("origin", "matrix"))

            self.log(f"[SORA] 🟢 Job queued → {job_id}")

        except Exception as e:
            self.log("[SORA][PROMPT][ERROR]", error=e)

    # ------------------------------------------------------------
    # WORKER LOOP
    # ------------------------------------------------------------
    def worker(self, config=None, identity=None):
        """Main worker cycle: process and poll jobs."""
        if self.running:
            self._emit_beacon()

            # Process queued jobs
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

        self.log("[SORA] Shutdown requested.")
        interruptible_sleep(self, 1)

    # ------------------------------------------------------------
    # START JOB (Submit to OpenAI)
    # ------------------------------------------------------------
    def _start_job(self, job_id, job_dir, state):
        try:
            prompt_data = self._load_json(os.path.join(job_dir, "prompt.json"))
            prompt = prompt_data.get("prompt")

            with self._cfg_lock:
                client = self.client
                model = self.model
                resolution = self.resolution

            resp = client.videos.generate(model=model, prompt=prompt, size=resolution)
            openai_job_id = resp.id

            state.update({"status": "pending_openai", "openai_job_id": openai_job_id, "progress": 0})
            self._save_json(os.path.join(job_dir, "state.json"), state)

            # Update DB
            sql = """
            UPDATE sora_jobs SET status='pending_openai', openai_job_id=%s, updated_at=NOW()
            WHERE openai_job_id=%s OR prompt=%s
            """
            self._db_run(sql, (openai_job_id, job_id, prompt))

            self.log(f"[SORA] 🚀 Submitted job {job_id} → OpenAI {openai_job_id}")

        except Exception as e:
            self.log("[SORA][SUBMIT][ERROR]", error=e)
            state.update({"status": "error", "error": "submit_failed"})
            self._save_json(os.path.join(job_dir, "state.json"), state)

    # ------------------------------------------------------------
    # POLL JOB (Check Progress / Completion)
    # ------------------------------------------------------------
    def _poll_job(self, job_id, job_dir, state):
        try:
            openai_id = state.get("openai_job_id")
            if not openai_id:
                return

            with self._cfg_lock:
                client = self.client

            status_resp = client.videos.status(openai_id)
            current_state = status_resp.state.lower()

            if current_state == "completed":
                file_bytes = client.videos.get(openai_id)
                out_dir = os.path.join(job_dir, "out")
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, "final.mp4")

                with open(out_path, "wb") as f:
                    f.write(file_bytes)

                state.update({"status": "done", "end_ts": int(time.time()), "output_file": "final.mp4"})
                self._save_json(os.path.join(job_dir, "state.json"), state)
                shutil.copy2(out_path, os.path.join(self.outbox_dir, f"{job_id}.mp4"))

                sql = "UPDATE sora_jobs SET status='done', updated_at=NOW() WHERE openai_job_id=%s"
                self._db_run(sql, (openai_id,))

                self.log(f"[SORA] ✅ Job complete → {openai_id}")
                self._record_video_metadata(job_id, out_dir)

            elif current_state in ("failed", "error"):
                state.update({"status": "error", "error": "generation_failed"})
                self._save_json(os.path.join(job_dir, "state.json"), state)
                sql = "UPDATE sora_jobs SET status='error', updated_at=NOW() WHERE openai_job_id=%s"
                self._db_run(sql, (openai_id,))
                self.log(f"[SORA] ❌ Job failed → {job_id}")

            elif current_state in ("running", "processing", "pending"):
                progress = getattr(status_resp, "progress", 0)
                state["progress"] = progress
                self._save_json(os.path.join(job_dir, "state.json"), state)
                sql = "UPDATE sora_jobs SET progress=%s, updated_at=NOW() WHERE openai_job_id=%s"
                self._db_run(sql, (progress, openai_id))
                self.log(f"[SORA] ⏳ {job_id} progress={progress}%")

            else:
                self.log(f"[SORA][WARN] Unknown state={current_state} for job {job_id}")

        except Exception as e:
            self.log("[SORA][POLL][ERROR]", error=e)
            state.update({"status": "error", "error": "poll_failed"})
            self._save_json(os.path.join(job_dir, "state.json"), state)
            sql = "UPDATE sora_jobs SET status='error', updated_at=NOW() WHERE openai_job_id=%s"
            self._db_run(sql, (state.get("openai_job_id"),))

    # ------------------------------------------------------------
    # RECORD VIDEO METADATA
    # ------------------------------------------------------------
    def _record_video_metadata(self, job_id, out_dir):
        """Optional: Log video into global video_video table for metrics."""
        try:
            sql = """
            INSERT INTO sora_outputs (job_id, file_path, resolution, completed_at)
            VALUES (
                (SELECT id FROM sora_jobs WHERE openai_job_id=%s LIMIT 1),
                %s, %s, NOW()
            )
            """
            file_path = os.path.join(out_dir, "final.mp4")
            self._db_run(sql, (job_id, file_path, self.resolution))
        except Exception as e:
            self.log("[SORA][DB][OUTPUT][ERROR]", error=e)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
