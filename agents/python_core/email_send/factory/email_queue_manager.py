# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Commander Edition — Email Snake-Tail Queue
import time, threading

class EmailQueueManager:
    MAX_ACTIVE = 10
    MAX_QUEUE = 10
    WORKER_TIMEOUT = 30  # seconds before kill

    def __init__(self, log, thread_launcher):
        self.log = log
        self.thread_launcher = thread_launcher

        self.log(f"[EMAIL_QUEUE] Manager instance id={id(self)} created")

        self.active = {}  # worker_id -> start_time
        self.queue = []  # FILO stack for payloads
        self.lock = threading.Lock()
        self.running = True

        # Spawn manager thread
        threading.Thread(target=self._loop, daemon=True).start()
        self.log("[EMAIL_QUEUE] Manager operational.")

    # ------------------------------------------------------------------
    def enqueue(self, payload):
        with self.lock:
            if len(self.queue) >= self.MAX_QUEUE:
                dropped = self.queue.pop(0)
                self.log(f"[EMAIL_QUEUE] ⚠️ Dropped oldest queued email (FILO).")

            self.queue.append(payload)
            self.log(f"[EMAIL_QUEUE] 📬 Enqueued email. Queue size={len(self.queue)}")

    # ------------------------------------------------------------------
    def _launch_worker(self, payload):
        context = {"payload": payload, "queue_manager": self}

        worker_id = self.thread_launcher.launch(
            "email_send.factory.email_sender_thread.EmailSenderThread",
            context=context,
            persist=False,
        )

        # Inject the ID directly into the existing context dict
        context["thread_id"] = worker_id

        self.active[worker_id] = time.time()
        self.log(f"[EMAIL_QUEUE] 🚀 Worker {worker_id} launched.")

    # ------------------------------------------------------------------
    def _cleanup_dead_workers(self):
        now = time.time()
        expired = [wid for wid, t0 in self.active.items()
                   if now - t0 > self.WORKER_TIMEOUT]

        for wid in expired:
            self.log(f"[EMAIL_QUEUE] ⚠️ Worker {wid} timed out — auto cleanup.")
            self.active.pop(wid, None)

    # ------------------------------------------------------------------
    def thread_finished(self, worker_id):
        self.log(f"[EMAIL_QUEUE] thread_finished called on id {id(self)} "
                 f"active={len(self.active)} before pop")
        with self.lock:
            if worker_id in self.active:
                self.log(f"[EMAIL_QUEUE] 🧹 Worker {worker_id} reported completion — removing from active.")
                self.active.pop(worker_id, None)

        self.last_activity = time.time()
        # kick the manager thread
        try:
            threading.Thread(target=self._drain_once, daemon=True).start()
        except Exception as e:
            self.log(f"[EMAIL_QUEUE] wake failed: {e}")

    def _drain_once(self):
        with self.lock:
            while len(self.active) < self.MAX_ACTIVE and self.queue:
                payload = self.queue.pop()
                self._launch_worker(payload)

    def _loop(self):
        self.log("[EMAIL_QUEUE] Loop thread started.")
        try:
            while self.running:
                time.sleep(0.25)
                with self.lock:
                    self._cleanup_dead_workers()
                    while len(self.active) < self.MAX_ACTIVE and self.queue:
                        payload = self.queue.pop()
                        self._launch_worker(payload)
        except Exception as e:
            import traceback
            self.log(f"[EMAIL_QUEUE] FATAL: queue loop crashed {e}\n{traceback.format_exc()}")
