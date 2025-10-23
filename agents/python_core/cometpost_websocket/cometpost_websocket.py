# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import os
import sys
import ssl
import time
import json
import base64
import asyncio
import random
import threading
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from hashlib import sha256


from collections import deque
from core.python_core.utils.cert_loader import load_cert_chain_from_memory
from core.python_core.utils.swarm_trustkit import extract_spki_pin_from_cert
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.security.packet_size import guard_packet_size
from core.python_core.utils.crypto_utils import pem_fix
from core.python_core.boot_agent import BootAgent

import websockets

class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        self.AGENT_VERSION = "3.1.0"

        config = self.tree_node.get("config", {})
        self.allowlist_ips = config.get("allowlist_ips", [])
        self.port = config.get("port", 8765)

        self._websocket_clients = set()
        self._seen_ids = {}
        self._comet_addresses = set(config.get("addresses", []))  # from directive or Phoenix push

        self.loop = None
        self._thread = None
        self._stop_event = threading.Event()
        self._queued_hashes = set()

        self.metrics = {
            "comets_seen": 0,
            "comets_dropped": 0,
            "comets_relayed": 0,
            "comets_to_op": 0,
            "comets_invalid_sig": 0,
            "comets_duplicate": 0,
            "comets_snatched": 0
        }

        # TLS info (optional, not required for anon edge)
        security = config.get("security", {}).get("connection", {})
        signing = config.get("security", {}).get("signing", {})

        self.cert_pem = pem_fix(security.get("server_cert", {}).get("cert", ""))
        self.key_pem = pem_fix(security.get("server_cert", {}).get("key", ""))
        self.ca_pem = pem_fix(security.get("ca_root", {}).get("cert", ""))

        self.local_spki = extract_spki_pin_from_cert(self.cert_pem.encode()) if self.cert_pem else None
        self.peer_pub_key = RSA.import_key(signing.get("remote_pubkey", "").encode()) if signing.get("remote_pubkey") else None

        self.ws_priv = RSA.import_key(signing.get("privkey", "").encode()) if signing.get("privkey") else None

        self._trusted_senders = {}

        self._outbound_queue = deque(maxlen=100)
        self._queue_lock = threading.Lock()
        self._dispatch_timer = None

    def post_boot(self):
        self.log(f"[COMETPOST] CometPost v{self.AGENT_VERSION} online.")

    def worker(self, *_):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._start_loop, daemon=True)
        self._thread.start()

        while not self._stop_event.is_set():
            interruptible_sleep(self, 10)

    def _start_loop(self):
        try:
            self.loop.create_task()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._launch_ws())
            self.loop = asyncio.new_event_loop()
            self.loop.create_task(self._drain_queue())
        except Exception as e:
            self.log(error=e, level="ERROR", block="main_try")


    def enqueue_relay(self, packet):
        try:
            packet_hash = sha256(json.dumps(packet, sort_keys=True).encode()).hexdigest()

            if packet_hash in self._queued_hashes:
                self.metrics["comets_duplicate"] += 1
                return

            with self._queue_lock:
                if len(self._outbound_queue) >= self._outbound_queue.maxlen:
                    self.log("[COMETPOST] Queue full. Packet dropped.")
                    return

                self._outbound_queue.append((packet_hash, packet))
                self._queued_hashes.add(packet_hash)

        except Exception as e:
            self.log("[COMETPOST] enqueue_relay failed", error=e)

    async def _drain_queue(self):
        while self.running:
            await asyncio.sleep(0.1)

            with self._queue_lock:
                if not self._outbound_queue:
                    continue
                packet_hash, packet = self._outbound_queue.popleft()
                self._queued_hashes.discard(packet_hash)

            await self._relay_to_peers(packet)

    def shutdown(self):
        self._stop_event.set()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread and self._thread.is_alive():
            self._thread.join()
        self.log("[COMETPOST] Shutdown complete.")


    async def _launch_ws(self):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.verify_mode = ssl.CERT_NONE

        if self.cert_pem and self.key_pem:
            load_cert_chain_from_memory(ssl_context, self.cert_pem, self.key_pem)

        try:
            server = await websockets.serve(
                self._websocket_handler,
                host="0.0.0.0",
                port=self.port,
                ssl=ssl_context,
                ping_interval=20,     # Ping every 20s (adjust as needed)
                ping_timeout=10       # Wait 10s for pong
            )

            self.log(f"[COMETPOST] Listening on port {self.port}")
            await server.wait_closed()
        except Exception as e:
            self.log("[COMETPOST] WebSocket failed", error=e)

    async def _websocket_handler(self, websocket):
        peer_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        if self.allowlist_ips and peer_ip not in self.allowlist_ips:
            self.log(f"[COMETPOST] Connection from {peer_ip} blocked by allowlist.")
            await websocket.close()
            return

        self._websocket_clients.add(websocket)
        try:
            await websocket.send("Welcome to CometPost. Perfect packets only. No retries. No storage.")
            await self._relay_loop(websocket)
        finally:
            self._websocket_clients.discard(websocket)

    async def _relay_loop(self, websocket):
        while True:
            try:
                raw = await websocket.recv()
                comet = json.loads(raw)
                self.metrics["comets_seen"] += 1
                if self._validate_comet(comet):
                    await self._handle_incoming_comet(comet)
                else:
                    continue  # silent drop
            except Exception:
                break

    def cmd_register_trusted_sender(self, content, packet, identity):
        """
        Allows Phoenix to register one or more trusted comet senders.

        content = {
          "v": "1",                            // optional version
          "to": "token_abc123...",             // 32-char token (recipient)
          "aes_key": "base64(...)",            // AES key encrypted with recipient pubkey
          "iv": "base64(...)",                 // AES IV (16 bytes)
          "msg": "base64(...)",                // payload ≤ 280 bytes (post-encryption)
          "ts": 1738888823,                   // timestamp
          "sig": "base64(...)"                // sender's signature over all fields above
        }
        """
        try:
            now = int(time.time())
            entries = content.get("entries", [])
            added = 0

            for entry in entries:
                token = entry.get("token")
                pub_pem = entry.get("pubkey")
                ttl = entry.get("ttl", 60)
                sig_required = entry.get("sig_required", True)

                if not token or not pub_pem:
                    continue

                pub_obj = RSA.import_key(pub_pem.encode())
                self._trusted_senders[token] = {
                    "pubkey": pub_obj,
                    "sig_required": sig_required,
                    "expire_at": now + ttl
                }
                added += 1

            self.log(f"[COMETPOST] Registered {added} trusted comet sender(s).")

        except Exception as e:
            self.log("[COMETPOST] Failed to register trusted sender", error=e)


    async def _relay_to_peers(self, packet, exclude=None):
        encoded = json.dumps(packet)
        peers = list(self._websocket_clients - {exclude} if exclude else self._websocket_clients)
        fanout = min(3, len(peers))
        chosen_peers = random.sample(peers, fanout) if len(peers) >= fanout else peers
        self.metrics["comets_relayed"] += 1
        for peer in chosen_peers:
            try:
                await peer.send(encoded)
            except:
                self._websocket_clients.discard(peer)
                self.log("[COMETPOST] Dropped disconnected peer.")


    def _validate_comet(self, comet: dict) -> bool:
        self.metrics["comets_dropped"] += 1
        if not isinstance(comet, dict):
            return False
        try:
            if not self.guard_cometpost_packet(comet):
                return False

            #drop if comet is not in 60 windows one way or the other
            ts = comet.get("ts")
            now = int(time.time())
            if not isinstance(ts, int) or abs(now - ts) > 60:
                self.log(f"[COMETPOST][DROP] Expired or invalid timestamp: {ts}")
                return False

            self.metrics["comets_dropped"] -= 1
            return True

        except Exception as e:
            self.log("[COMETPOST][DROP] Malformed comet packet", error=e)
            return False

    def _validate_signature(self, comet: dict, token: str) -> bool:
        try:
            sender = self._trusted_senders.get(token)
            if not sender:
                return False

            if int(time.time()) > sender.get("expire_at", 0):
                del self._trusted_senders[token]
                return False

            if sender.get("sig_required", True):
                sig = comet.get("sig")
                if not sig:
                    return False

                try:
                    payload = {k: v for k, v in comet.items() if k != "sig"}
                    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                    digest = SHA256.new(serialized)
                    pkcs1_15.new(sender["pubkey"]).verify(digest, base64.b64decode(sig))
                except Exception:
                    return False

            return True

        except Exception as e:
            self.log("[COMETPOST] Signature check failed", error=e)
            return False

    async def _handle_incoming_comet(self, comet):
        try:
            address = comet.get("to")
            if address == "op":
                self.metrics["comets_to_op"] += 1

            # Snatch if addressed to us and valid
            elif address in self._trusted_senders:
                if self._validate_signature(comet, address):
                    self.metrics["comets_snatched"] += 1
                else:
                    self.metrics["comets_invalid_sig"] += 1
                    return

            # Always enqueue for relay
            self.enqueue_relay(comet)

        except Exception as e:
            self.log("[COMETPOST] Relay fail", error=e)

    def guard_cometpost_packet(self, pk):

        try:
            # Field constraints
            FIELD_RULES = {
                "to":      (str, 32, 32),    # fixed-length token - address
                "aes_key": (str, 128, 400),
                "iv":      (str, 16, 32),
                "msg":     (str, 1, 512),
                "sig":     (str, 128, 400),
                "v":       (str, 1, 8),
            }

            # Required fields
            for k in ("to", "aes_key", "iv", "msg", "ts", "sig"):
                if k not in pk:
                    self.log(f"[COMETPOST][DROP] Missing required field: {k}")
                    return False

            # Type and size checks
            for k, (typ, min_len, max_len) in FIELD_RULES.items():
                if k in pk:
                    if not isinstance(pk[k], typ):
                        self.log(f"[COMETPOST][DROP] Field {k} wrong type")
                        return False
                    l = len(pk[k])
                    if l < min_len or l > max_len:
                        self.log(f"[COMETPOST][DROP] Field {k} invalid size ({l})")
                        return False

            # ts
            if not isinstance(pk["ts"], int):
                self.log("[COMETPOST][DROP] ts is not an int")
                return False

            # Total JSON size (as last line of defense)
            total_size = len(json.dumps(pk, ensure_ascii=False).encode("utf-8"))
            if total_size > 2048:
                self.log(f"[COMETPOST][DROP] Packet size {total_size} > 2048")
                return False

            return True

        except Exception as e:
            self.log(error=e, level="WARNING", block="main_try")
            return False

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
