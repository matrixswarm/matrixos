import time
from collections import deque

class ReplayGuard:
    def __init__(self, ttl_seconds=60):
        self.seen = {}
        self.ttl = ttl_seconds

    def is_replay(self, packet):
        nonce = packet.get("nonce")
        timestamp = packet.get("timestamp")

        if not nonce or not timestamp:
            return True  # Invalid structure = block

        now = int(time.time())

        if now - timestamp > self.ttl:
            return True  # Too old = possible replay

        if nonce in self.seen:
            return True  # Already seen = replay

        # Store nonce with expiration
        self.seen[nonce] = now
        self._evict_old_entries(now)
        return False

    def _evict_old_entries(self, now):
        expired = [k for k, v in self.seen.items() if now - v > self.ttl]
        for k in expired:
            del self.seen[k]
