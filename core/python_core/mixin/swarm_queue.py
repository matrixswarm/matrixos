# SwarmQueueMixin — Enables queue-based asynchronous resolution requests for any agent
import os
import json
import time
import uuid

class SwarmQueueMixin:
    def init_queue_path(self):
        self.queue_path = os.path.join(self.path_resolution["comm_path_resolved"], "payload")
        os.makedirs(self.queue_path, exist_ok=True)

    def create_queue_file(self, label, original_packet):
        ts = int(time.time())
        qid = uuid.uuid4().hex[:12]
        fname = f"{qid}_{label}_{ts}_que.cmd"
        fpath = os.path.join(self.queue_path, fname)
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump({
                    "queue_id": qid,
                    "timestamp": ts,
                    "label": label,
                    "original_packet": original_packet
                }, f, indent=2)
            self.log(f"[QUEUE] Created queue file: {fname}")
            return qid
        except Exception as e:
            self.log(f"[QUEUE][ERROR] Failed to create queue file: {e}")
            return None

    def handle_resolve_response(self, packet):
        qid = packet.get("queue_id")
        if not qid:
            self.log("[QUEUE][ERROR] No queue_id in response.")
            return

        match = None
        for fname in os.listdir(self.queue_path):
            if fname.startswith(qid) and fname.endswith("_que.cmd"):
                match = os.path.join(self.queue_path, fname)
                break

        if not match:
            self.log(f"[QUEUE][MISS] No matching queue file for {qid}")
            return

        try:
            with open(match, "r", encoding="utf-8") as f:
                que_data = json.load(f)
            payload = que_data.get("original_packet")
            results = packet.get("results")

            if payload and results:
                # Inject result into the packet (e.g., fill in target)
                payload["content"]["target_universal_id"] = results[0]  # Simple fallback
                self.route_final_payload(payload)

            os.remove(match)
            self.log(f"[QUEUE] Processed and removed queue file: {match}")
        except Exception as e:
            self.log(f"[QUEUE][FAIL] Failed to process queue file {match}: {e}")

    def route_final_payload(self, payload):
        """
        Override this in agent to determine how to send resolved packet
        """
        self.log(f"[QUEUE][DEBUG] Would route: {json.dumps(payload, indent=2)}")