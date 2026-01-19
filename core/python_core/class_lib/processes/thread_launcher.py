import importlib
import threading
import time
import uuid
import traceback

class ThreadLauncher:
    """
    ThreadLauncher — Swarm Thread Orchestrator
    ------------------------------------------
    • Dynamically loads classes
    • Executes them as managed threads
    • Supports ephemeral and persistent workers
    • Centralized logging via BootAgent.log
    """

    def __init__(self, boot_agent):
        self.agent = boot_agent
        self.log = boot_agent.log

        self._threads = {}        # thread_id -> Thread
        self._registry = {}       # thread_id -> metadata
        self._shared_state = {}   # thread_id -> shared dict
        self._lock = threading.Lock()

        self.log("ThreadLauncher initialized")

    # --------------------------------------------------
    def launch(
        self,
        class_path: str,
        context: dict | None = None,
        persist: bool = False,
        check_interval: int = 30,
    ) -> str:
        """
        Launch a class as a managed thread.

        class_path:
            agent.<agent_name>.factory.<module>.<Class>

        persist:
            False → fire-and-forget
            True  → monitored, heartbeat-required

        context:
            dict passed to worker
        """

        thread_id = uuid.uuid4().hex
        context = context or {}

        try:
            self.log(f"Launching thread {class_path} persist={persist}")

            cls = self._load_class(class_path)

            shared = {
                "thread_id": thread_id,
                "class_path": class_path,
                "started_at": time.time(),
                "last_heartbeat": time.time(),
                "stop": False,
                "context": context,
            }

            with self._lock:
                self._shared_state[thread_id] = shared
                self._registry[thread_id] = {
                    "class_path": class_path,
                    "persist": persist,
                    "check_interval": check_interval,
                    "started_at": time.time(),
                }

            def runner():
                try:
                    self.log(f"Thread {thread_id} entering runner")

                    instance = cls(
                        log=self.log,
                        shared=shared,
                    )

                    if not hasattr(instance, "run"):
                        raise AttributeError(
                            f"{class_path} has no run() method"
                        )

                    instance.run()

                    self.log(f"Thread {thread_id} completed normally")

                except Exception as e:
                    self.log(
                        error=e,
                        block="thread_runner",
                        level="ERROR",
                    )
                    self.log(
                        traceback.format_exc(),
                        block="thread_runner_trace",
                        level="DEBUG",
                    )

                finally:
                    self._cleanup(thread_id)

            t = threading.Thread(
                target=runner,
                name=f"thread:{class_path}",
                daemon=True,
            )

            with self._lock:
                self._threads[thread_id] = t

            t.start()
            self.log(f"Thread {thread_id} started")

            return thread_id

        except Exception as e:
            self.log(
                error=e,
                block="thread_launch",
                level="ERROR",
            )
            raise

    # --------------------------------------------------
    def monitor(self):
        """
        Monitor persistent threads.
        Call this from the parent agent worker loop.
        """
        now = time.time()

        try:
            with self._lock:
                for tid, meta in list(self._registry.items()):
                    if not meta.get("persist"):
                        continue

                    shared = self._shared_state.get(tid)
                    if not shared:
                        continue

                    last = shared.get("last_heartbeat", 0)
                    interval = meta.get("check_interval", 30)

                    if now - last > interval * 2:
                        self.log(
                            f"Thread {tid} ({meta['class_path']}) heartbeat stale "
                            f"delta={int(now - last)}s",
                            block="thread_monitor",
                            level="WARN",
                        )

        except Exception as e:
            self.log(
                error=e,
                block="thread_monitor",
                level="ERROR",
            )

    # --------------------------------------------------
    def stop(self, thread_id: str):
        """
        Signal a thread to stop gracefully.
        """
        try:
            with self._lock:
                shared = self._shared_state.get(thread_id)
                if not shared:
                    self.log(
                        f"Stop requested for unknown thread {thread_id}",
                        block="thread_stop",
                        level="WARN",
                    )
                    return

                shared["stop"] = True
                self.log(f"Stop signal sent to thread {thread_id}")

        except Exception as e:
            self.log(
                error=e,
                block="thread_stop",
                level="ERROR",
            )

    # --------------------------------------------------
    def _cleanup(self, thread_id: str):
        """
        Internal cleanup after thread exit.
        """

        try:
            with self._lock:
                meta = self._registry.pop(thread_id, None)
                self._threads.pop(thread_id, None)
                self._shared_state.pop(thread_id, None)

            if meta:
                self.log(
                    f"Thread {thread_id} cleaned up "
                    f"({meta.get('class_path')})",
                    block="thread_cleanup",
                )
            else:
                self.log(
                    f"Thread {thread_id} cleanup with no registry entry",
                    block="thread_cleanup",
                    level="WARN",
                )

        except Exception as e:
            self.log(
                error=e,
                block="thread_cleanup",
                level="ERROR",
            )

    # --------------------------------------------------
    def _load_class(self, dotted_path: str):
        """
        Dynamically load a class from a dotted path.
        """

        try:

            self.log(f"Loading class {dotted_path}", block="class_loader")

            module_path, class_name = dotted_path.rsplit(".", 1)
            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)

            self.log(f"Loaded class {dotted_path}", block="class_loader")
            return cls

        except Exception as e:
            self.log(
                error=e,
                block="class_loader",
                level="ERROR",
            )
            raise

    # --------------------------------------------------
    def get_shared(self, thread_id: str):
        """
        Return the shared context dictionary for a running thread.
        Used by queue managers and other controllers that need to
        inject or read data after launch.
        """
        try:
            with self._lock:
                shared = self._shared_state.get(thread_id)
                if not shared:
                    self.log(
                        f"get_shared: unknown thread {thread_id}",
                        block="thread_get_shared",
                        level="WARN",
                    )
                    return None
                return shared
        except Exception as e:
            self.log(
                error=e,
                block="thread_get_shared",
                level="ERROR",
            )
            return None

