import time
from collections import defaultdict

class JediEventFlow:
    """
    Event Coalescing Engine
    Compresses inotify spam into a single narrative line per file.
    """

    def __init__(self, delay=0.20, logger=None):
        self.delay = delay
        self.logger = logger or print  # fallback to console
        self.events = defaultdict(lambda: {
            "created": False,
            "modified": False,
            "quarantined": False,
            "moved": False,
            "ts": 0
        })

        # fallout suppression
        self.last_quarantine = {}

    # --- PUBLIC API -------------------------------------------------------

    def record(self, path, kind):
        """Record an event for this path."""
        st = self.events[path]
        st[kind] = True
        st["ts"] = time.time()

    def mark_quarantine(self, path):
        """Record that a file was quarantined now."""
        self.last_quarantine[path] = time.time()
        self.record(path, "quarantined")

    def fallout(self, path, window=1.5):
        """Return True if we should ignore the event as fallout."""
        last = self.last_quarantine.get(path, 0)
        return (time.time() - last) < window

    def flush(self):
        """Emit narrative lines for all completed flows."""
        now = time.time()
        expired = []

        for path, st in list(self.events.items()):
            if now - st["ts"] < self.delay:
                continue

            flow = []
            if st["created"]: flow.append("created")
            if st["modified"]: flow.append("modified")
            if st["quarantined"]: flow.append("quarantined")
            if st["moved"]: flow.append("moved_from")

            if flow:
                self.logger(f"[TRIPWIRE][FLOW] {path} → " + " → ".join(flow))

            expired.append(path)

        for p in expired:
            del self.events[p]
