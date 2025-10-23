# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini Docstrings
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import ssl
import time
import copy
import threading
import asyncio
import websockets
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.utils.swarm_trustkit import extract_spki_pin_from_cert
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.crypto_utils import pem_fix
from core.python_core.utils.cert_loader import load_cert_chain_from_memory
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.utils import crypto_utils
from core.python_core.class_lib.packet_delivery.utility.security.packet_size import guard_packet_size

class Agent(BootAgent):
    """
    The Matrix WebSocket Agent, a specialized BootAgent for secure,
    bidirectional communication with front-end applications.

    This agent extends the core `BootAgent` functionality with a secure
    WebSocket server. It's designed to provide a real-time, authenticated
    data feed for human-in-the-loop interfaces, such as a GUI. It enforces
    strict security checks, including mTLS and cryptographic signature
    verification, to ensure only trusted clients can connect and exchange
    messages. It also manages active client sessions and broadcasts messages
    to connected clients.

    Attributes:
        AGENT_VERSION (str): The version of the agent.
        allowlist_ips (list): A list of IP addresses permitted to connect.
        port (int): The network port the WebSocket server listens on.
        _websocket_clients (set): A set of active WebSocket connections.
        _sessions (dict): A dictionary mapping session IDs to connection data.
        loop (asyncio.AbstractEventLoop): The asyncio event loop running the server.
        websocket_ready (bool): A flag indicating if the WebSocket server is bound.
        interval (int): The sleep interval for the worker loop.
        first_run (bool): A flag to indicate the first execution of the worker.
        cert_pem (str): The agent's TLS certificate in PEM format.
        key_pem (str): The agent's private key in PEM format.
        ca_pem (str): The CA root certificate for client verification.
        local_spki (str): The SHA-256 SPKI pin of the agent's server certificate.
        peer_pub_key (Crypto.PublicKey.RSA): The public key used to verify
            signatures on incoming messages.
        ws_priv (Crypto.PublicKey.RSA): The private key used to sign outbound messages.
        _stop_event (threading.Event): An event used to signal the WebSocket thread to stop.
        _thread (threading.Thread): The thread running the WebSocket server.
        _config (dict): A copy of the agent's most recent configuration.
        _lock (threading.Lock): A lock to protect access to shared resources.
        emit_process_beacon (function): A beacon to signal the process is alive.
        emit_service_beacon (function): A beacon to signal the service is healthy.

    Methods:
        post_boot():
            Logs a message confirming the agent is fully operational.

        worker():
            Manages the lifecycle of the WebSocket thread, starting it on
            first run or restarting it if the configuration changes or the
            thread has died.

        start_socket_loop():
            Initializes and runs the asyncio event loop for the WebSocket server,
            setting up the SSL context and handling server startup.

        websocket_handler():
            A wrapper for the main handler to catch top-level exceptions.

        _websocket_handler_core():
            The core handler for new WebSocket connections. It performs
            multi-layered security checks, including IP allowlisting and
            cryptographic signature verification on the initial handshake.
            It also sets up a session and a keep-alive ping for the client.

        update_broadcast_flag():
            Creates or removes a file flag to signal other parts of the system
            that a GUI is connected, which can be used to trigger alerts.

        cmd_rpc_route():
            Routes an RPC-style packet to a specific client session if a session
            ID is provided. If not, it broadcasts the packet to all clients.

        cmd_send_alert_msg():
            A command handler that formats and dispatches an alert message to
            all connected GUI clients.

        _canon(obj):
            A static helper method to create a canonical, sorted JSON string
            for consistent signing.

        _now():
            A static helper method to get the current timestamp.

        _sign_content(content):
            Signs a dictionary using the agent's private key and returns a
            base64-encoded signature.

        cmd_alert_to_gui():
            Dispatches a formatted alert to all connected GUI clients via
            the WebSocket.

        cmd_hive_log_delivery():
            Handles requests to retrieve and format log files, then broadcasts
            the content to a connected GUI client.

        decrypt_log_line():
            A placeholder for a method to decrypt a single line of an encrypted
            log file.

        cmd_broadcast():
            Broadcasts a message to all currently connected WebSocket clients
            using a thread-safe coroutine.
        """
    def __init__(self):
        """
        Initializes the Matrix WebSocket agent.

        It first calls the parent `BootAgent` constructor, then securely
        loads TLS certificates and keys from the agent's directive. It
        sets up state variables for managing WebSocket connections and
        prepares the agent for network communication.
        """
        super().__init__()
        self.AGENT_VERSION = "2.0.1"

        try:

            config = self.tree_node.get("config", {})
            self.allowlist_ips = config.get("allowlist_ips", [])
            self.port = config.get("port", 8765)
            self._websocket_clients = set()
            self._sessions = {}
            self.loop = None
            self.websocket_ready = False
            self.interval = 10
            self.first_run = True

            security = self.tree_node.get("config", {}).get("security", {})  # dict now
            conn = security.get("connection", {}) or {}

            server_cert = conn.get("server_cert", {})
            client_cert = conn.get("client_cert", {})
            ca_root = conn.get("ca_root", {})

            self.cert_pem = pem_fix(server_cert.get("cert"))
            self.key_pem = pem_fix(server_cert.get("key"))
            self.ca_pem = pem_fix(ca_root.get("cert"))

            # Compute SPKI pin directly from memory
            try:
                self.local_spki = extract_spki_pin_from_cert(self.cert_pem.encode())
            except Exception as e:
                self.local_spki = None
                self.log("[WS][SPKI][WARN] Could not compute local SPKI pin", error=e)

            # --- Suspenders: load our signing private key (minted & embedded at deploy)
            signing_cfg = security.get("signing", {})
            peer_pub_pem = signing_cfg.get("remote_pubkey")
            self.peer_pub_key = RSA.import_key(peer_pub_pem.encode()) if peer_pub_pem else None
            ws_priv_pem = signing_cfg.get("privkey")
            try:
                self.ws_priv = RSA.import_key(ws_priv_pem.encode()) if ws_priv_pem else None
                if self.ws_priv:
                    self.log("[WS][SIGN] Private key loaded for outbound signing.")
                else:
                    self.log("[WS][SIGN][WARN] No signing privkey present in config.security.signing.privkey")
            except Exception as e:
                self.ws_priv = None
                self.log("[WS][SIGN][ERROR] Failed to load signing private key", error=e)

            self.log("[CERT-LOADER] Embedded certs loaded into memory.")

        except Exception as e:
            self.log("[CERT-LOADER][FATAL] Failed to load certs from config.security.connection", error=e, block="init")
            time.sleep(2)
            self.run_server_retries = False


        self._stop_event = None
        self._thread = None
        self._config = None
        self._lock = threading.Lock()
        self.emit_process_beacon = self.check_for_thread_poke(
            "websocket_process", timeout=60, emit_to_file_interval=30
        )
        self.emit_service_beacon = self.check_for_thread_poke(
            "websocket_service", timeout=60, emit_to_file_interval=30
        )

    def post_boot(self):
        """
        A one-time setup hook called after the main threads have started.

        This method is overridden to log a confirmation that the agent is
        fully operational and the perimeter guard is in place.
        """
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – perimeter guard up.")

    def worker(self, config:dict = None, identity:IdentityObject = None):
        """
        The main operational loop for the agent, overridden from `BootAgent`.

        This method is responsible for managing the lifecycle of the WebSocket
        server thread. It ensures the server is started on the first run,
        restarted if the configuration changes, or restarted if the thread
        crashes unexpectedly. It also emits a process liveness beacon.

        Args:
            config (dict, optional): The latest configuration from a packet.
            identity (IdentityObject, optional): The identity of the packet sender.
        """
        try:

            self.emit_process_beacon()
            if config is None:
                config = self.tree_node.get("config", {})  # Default fallback

            with self._lock:
                if self._thread and self._thread.is_alive():
                    if config == self._config:
                        # Config unchanged, thread alive — do nothing
                        return
                    else:
                        self.log("[WS] Launching WebSocket thread... Or Config changed and restarting thread...")
                        self._stop_event.set()
                        self._thread.join(timeout=3)
                elif self._thread and not self._thread.is_alive():
                    self.log("[WS] Previous thread is dead — restarting...")

                # Start new thread
                self._config = copy.deepcopy(config)  # Defensive copy
                self._stop_event = threading.Event()
                self._thread = threading.Thread(target=self.start_socket_loop, daemon=True)
                self._thread.start()
                self.log("[WS] WebSocket thread started.")


        except Exception as e:

            self.log(error=e, block="main_try")

        interruptible_sleep(self, self.interval)


    def start_socket_loop(self):
        """
        Initializes and runs the asyncio event loop for the WebSocket server.

        This method is designed to run in a separate thread. It sets up the
        SSL context with mTLS requirements, binds the server to a host and port,
        and starts the event loop. It also schedules a service heartbeat beacon
        and a broadcast flag updater to run concurrently.
        """
        try:
            self.log("[WS] Booting WebSocket TLS thread...")
            time.sleep(1)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop

            async def launch():
                self.log("[WS] Preparing SSL context...")
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.verify_mode = ssl.CERT_REQUIRED

                if self.cert_pem and self.key_pem:
                    load_cert_chain_from_memory(ssl_context, self.cert_pem, self.key_pem)

                # Load CA root from memory if present
                if self.ca_pem:
                    ssl_context.load_verify_locations(cadata=self.ca_pem)
                    self.log("[WS][DEBUG] Loaded CA root from memory")
                else:
                    self.log("[WS][WARN] No client CA provided — clients may not present a cert")

                try:
                    server = await websockets.serve(
                        self.websocket_handler,
                        host="0.0.0.0",
                        port=self.port,
                        ssl=ssl_context,
                        ping_interval=None,
                        ping_timeout=None,
                    )

                    self.log("[WS][BOOT] Listener bound")
                except Exception as e:
                    self.log(f"[WS][BOOT ERROR] {e}")
                    return

                self.websocket_ready = True
                self.log(f"[WS] SECURE WebSocket bound on port {self.port} (TLS enabled)")

                # Service beacon heartbeat inside the loop
                async def service_heartbeat():
                    while not self._stop_event.is_set():
                        self.emit_service_beacon()
                        await asyncio.sleep(30)

                loop.create_task(service_heartbeat())

                async def refresh_broadcast_flag():
                    while not self._stop_event.is_set():
                        # bump all active session flags
                        for sid in list(self._sessions.keys()):
                            self.update_broadcast_flag(session_id=sid)
                        await asyncio.sleep(15)

                loop.create_task(refresh_broadcast_flag())

                await server.wait_closed()

            loop.run_until_complete(launch())

            async def monitor_stop():
                while not self._stop_event.is_set():
                    await asyncio.sleep(1)
                self.log("[WS] Stop event received — shutting down WebSocket server.")
                loop.stop()

            loop.create_task(monitor_stop())
            loop.run_forever()
            loop.close()
            self.log("[WS] Event loop closed.")

        except Exception as e:
            self.log("[WS][FATAL] WebSocket startup failed", error=e, block="main_try")
            self.running = False

    async def websocket_handler(self, websocket):
        """
        A wrapper for the main WebSocket handler.

        This function wraps the core handler to provide a consistent top-level
        exception catch, ensuring graceful closure even in case of unexpected
        errors.
        """
        try:
            await self._websocket_handler_core(websocket)
        except Exception as e:
            self.log(f"[WS][FATAL] websocket_handler crashed", error=e, block="main_try")
            try:
                await websocket.close(reason="handler crash")
            except:
                pass

    async def _websocket_handler_core(self, websocket):
        """
        The core handler for new WebSocket connections.

        This method orchestrates the connection lifecycle:
        1. It performs the initial handshake (`_handle_handshake`), which includes
           waiting for the 'hello' packet, signature verification, and session binding.
        2. If the handshake succeeds, it enters the message processing loop
           (`_handle_message_loop`) to handle all incoming signed packets.
        3. The `finally` block ensures proper session cleanup, including removing
           the client from the active set, popping the session from the dictionary,
           and removing the local broadcast flag.

        :param websocket: The incoming WebSocket connection object.
        :type websocket: websockets.WebSocketServerProtocol
        """
        try:

            ip = getattr(websocket, "remote_address", None)
            if isinstance(ip, tuple):
                ip = ip[0]
            else:
                ip = "unknown"
            self.log(f"[WS][CONNECT] Client connected from IP: {ip}")

            cert_bin = websocket.transport.get_extra_info("peercert", default=None)

            if not cert_bin:
                self.log(
                    f"[WS][NO CLIENT CERT] No client certificate presented by IP {ip} — cannot perform SPKI pin check")
                await websocket.close(reason="No client cert")
                return

            # Explicitly confirm the client is in allowlist (or no allowlist restriction)
            if self.allowlist_ips:
                if ip not in self.allowlist_ips:
                    self.log(f"[WS][SECURITY] IP {ip} explicitly blocked by allowlist")
                    await websocket.close(reason="Blocked by IP allowlist")
                    return
                else:
                    self.log(f"[WS][SECURITY] IP {ip} explicitly allowed by allowlist")
            else:
                self.log("[WS][SECURITY] No IP allowlist restriction in place")

            # ... cert + allowlist checks here ...

            # Phase 1: Handshake
            sid = await self._handle_handshake(websocket)
            if not sid:
                return

            # Phase 2: Message loop
            await self._handle_message_loop(websocket, sid)

        except Exception as e:
            self.log(f"[WS][FATAL] Handshake exception: {e}")
            await websocket.close(reason="Internal WebSocket exception")

        finally:
            self._websocket_clients.discard(websocket)
            if hasattr(websocket, "session_id"):
                sid = websocket.session_id
                self._sessions.pop(sid, None)
                self.update_broadcast_flag(session_id=sid, remove=True)
            self.log(f"[WS][CLEANUP] Client removed. Active={len(self._websocket_clients)}")

    async def _handle_handshake(self, websocket):
        """
        Performs the initial secure 'hello' handshake with the client.

        This critical phase enforces multiple security and session checks:
        1. Waits for a JSON 'hello' packet, expecting fields like "type" and "session_id".
        2. Verifies the packet's digital signature using the agent's known
           `peer_pub_key` to authenticate the client application.
        3. If successful, it binds the `session_id` to the WebSocket object,
           updates the `_sessions` dictionary, and starts an asynchronous keep-alive
           ping task for the client.
        4. Creates the local broadcast flag file to signal other agents that a
           GUI session is active.

        :param websocket: The active WebSocket connection.
        :type websocket: websockets.WebSocketServerProtocol
        :returns: The valid session ID (str) upon success, or None on failure.
        :rtype: str or None
        """
        try:
            handshake = await asyncio.wait_for(websocket.recv(), timeout=5)
            hello = json.loads(handshake)

            if hello.get("type") != "hello" or "session_id" not in hello:
                self.log("[WS][SESSION][WARN] Invalid hello packet, closing.")
                await websocket.close(reason="invalid hello")
                return None

            if "sig" not in hello:
                await websocket.close(reason="missing signature")
                return None

            try:
                crypto_utils.verify_signed_payload(hello, hello["sig"], self.peer_pub_key)
                self.log(f"[WS][HELLO] Signature Accepted")
            except Exception as e:
                self.log(f"[WS][HELLO][DENY] Bad signature: {e}")
                await websocket.close(reason="bad hello signature")
                return None

            sid = hello["session_id"]
            websocket.session_id = sid
            self._sessions[sid] = {
                "ws": websocket,
                "agent": hello.get("agent"),
                "started": time.time()
            }

            # Keepalive pinger
            async def ping_keepalive(ws, sid):
                while sid in self._sessions:
                    try:
                        await ws.ping()
                    except Exception:
                        break
                    await asyncio.sleep(10)

            self.loop.create_task(ping_keepalive(websocket, sid))
            self.update_broadcast_flag(session_id=sid)

            self.log(f"[WS][SESSION] Bound to session_id={sid}")
            return sid

        except Exception as e:
            self.log(f"[WS][SESSION][ERROR] Handshake failed: {e}")
            await websocket.close(reason="handshake failed")
            return None

    async def _handle_message_loop(self, websocket, sid):
        """
        Processes all incoming signed packets from an authenticated client session.

        This loop continuously waits for messages and applies a series of
        security and validation guards to every packet:
        1. **Structure Guard**: Ensures the packet structure is valid JSON.
        2. **Size Guard**: Prevents oversized payloads using `guard_packet_size`.
        3. **Timestamp / Replay Guard**: Checks the packet's timestamp (`ts`) to
           prevent replay attacks (must be within a 120-second window).
        4. **Signature Guard**: Verifies the digital signature (`sig`) using the
           `peer_pub_key`.
        Upon passing all checks, an acknowledgement (`ack`) is sent back to the client.

        :param websocket: The active WebSocket connection.
        :type websocket: websockets.WebSocketServerProtocol
        :param sid: The verified session ID of the client.
        :type sid: str
        """
        while True:
            try:
                raw = await websocket.recv()
                self.log(f"[WS][MESSAGE RECEIVED] {raw}")
                outer = json.loads(raw)

                sig_b64 = outer.get("sig")
                inner = outer.get("content", {})

                # --- Structure guard ---
                if not isinstance(inner, dict):
                    await websocket.send(json.dumps({"type": "error", "message": "bad packet format"}))
                    continue

                # --- Size guard ---
                if not guard_packet_size(inner, log=self.log):
                    await websocket.send(json.dumps({"type": "error", "message": "bad or oversized payload"}))
                    continue

                # --- Timestamp / Replay guard ---
                ts = inner.get("ts")
                try:
                    if not ts or abs(time.time() - float(ts)) > 120:
                        await websocket.send(json.dumps({"type": "error", "message": "stale or bad timestamp"}))
                        continue
                except Exception:
                    await websocket.send(json.dumps({"type": "error", "message": "bad timestamp format"}))
                    continue

                # --- Signature guard ---
                try:
                    crypto_utils.verify_signed_payload(inner, sig_b64, self.peer_pub_key)
                    data = inner
                    self.log(f"[WS][MSG] Signature Accepted")
                except Exception as e:
                    self.log(f"[WS][SIG DENY] {e}")
                    await websocket.close(reason="bad message signature")
                    break

                # --- Ack only if all guards pass ---
                await websocket.send(json.dumps({"type": "ack", "echo": data}))

            except websockets.ConnectionClosed as cc:
                self.log(f"[WS][DISCONNECT] Graceful disconnect ({cc.code}): {cc.reason}")
                break
            except json.JSONDecodeError:
                self.log("[WS][ERROR] Malformed JSON")
                await websocket.send(json.dumps({"type": "error", "message": "Malformed JSON"}))
            except Exception as e:
                self.log(f"[WS][ERROR] Unexpected: {e}")
                break

    def update_broadcast_flag(self, session_id=None, remove=False):
        """
        Creates or removes a local filesystem flag.

        This method is used to signal other processes or agents within the
        swarm that a GUI client is actively connected via WebSocket. The
        flag's presence can be used to trigger certain behaviors, such as
        sending real-time alerts.
        """
        base = os.path.join(self.path_resolution["comm_path_resolved"], "broadcast")
        os.makedirs(base, exist_ok=True)

        flag = os.path.join(base, f"connected.flag.{session_id}") if session_id else os.path.join(base, "connected.flag")

        if remove:
            if os.path.exists(flag):
                os.remove(flag)
            return

        open(flag, "w").close()
        os.utime(flag, None)

    def cmd_rpc_route(self, content, packet, identity:IdentityObject = None):
        """
        Routes an RPC-style packet to a specific GUI session.

        This command handler receives a packet, checks for a `session_id`, and
        if found, attempts to send the packet's content directly to that
        specific WebSocket client. If no `session_id` is specified or found,
        it falls back to broadcasting the message to all connected clients.
        """
        try:

            session_id = packet.get("session_id")
            #Note: never depend on origin, you should only depend on identity, and that is only live when encryption is turned on for the swarm
            #      because that is cryptigraphically certain to be the agent
            if identity and identity.has_verified_identity():
                sender=identity.get_sender_uid()
            else:
                sender=packet.get("origin", "not specified")

            if session_id and session_id in self._sessions:
                websocket = self._sessions[session_id]["ws"]
                if self.debug.is_enabled():
                    self.log(f"[WS][ROUTER] Directing to session {session_id} : Sender: {sender}")

                data = json.dumps(content, separators=(",", ":"), sort_keys=False)
                asyncio.run_coroutine_threadsafe(websocket.send(data), self.loop)

            else:
                if session_id:
                    self.log(f"[WS][ROUTER][DISPOSED] Session '{session_id}' not found — disposing: Sender: {sender}")
                else:
                    self.log("[WS][ROUTER] No session_id — broadcasting to all.")
                    self.cmd_broadcast(content, content)

        except Exception as e:
            self.log("[WS][ROUTER][ERROR] Failed to route RPC packet", error=e)


    def cmd_send_alert_msg(self, content, packet, identity:IdentityObject = None):
        """
        Sends an alert message to the connected GUI clients.

        This command handler formats an alert message from an incoming packet
        into a standard GUI-compatible format and then uses the broadcast
        method to send it to all active WebSocket clients.
        """
        try:
            # Format the alert message
            msg = content.get("formatted_msg") or content.get("msg") or "[SWARM] Alert received."

            # Construct GUI-style feed packet
            broadcast_packet = {
                "handler": "cmd_alert_to_gui",
                "origin": content.get("origin", "unknown"),
                "timestamp": time.time(),
                "content": {
                    "msg": msg,
                    "level": content.get("level", "info"),
                    "origin": content.get("origin", "unknown"),
                    "formatted_msg": msg
                }
            }

            # Dispatch it via WebSocket
            self.cmd_broadcast(broadcast_packet["content"], broadcast_packet)

            self.log("Alert message sent to GUI feed.")
        except Exception as e:
            self.log(error=e)  # Optional: write full trace to logs


    # --- Helper: stable canonical JSON (no whitespace, sorted keys)
    @staticmethod
    def _canon(obj: dict) -> bytes:
        """
        Converts a dictionary to a canonical JSON string.

        This method produces a consistent, compact JSON representation by
        removing whitespace and sorting keys. This is crucial for creating a
        stable payload that can be cryptographically signed and verified.

        Returns:
            bytes: The canonical JSON string as a byte sequence.
        """
        return json.dumps(obj or {}, separators=(",", ":"), sort_keys=True).encode()

    @staticmethod
    def _now() -> float:
        """
        Returns the current timestamp.
        """
        return time.time()

    def _sign_content(self, content: dict) -> str:
        """
        Returns a base64-encoded RS256 signature over canonicalized content.

        This private method signs a given dictionary by first converting it
        into a canonical JSON string and then using the agent's private key
        to create a digital signature.

        Returns:
            str: The base64-encoded signature, or an empty string if no
                 private key is available.
        """
        if not self.ws_priv:
            return ""
        h = SHA256.new(self._canon(content))
        sig = pkcs1_15.new(self.ws_priv).sign(h)
        return base64.b64encode(sig).decode()


    def cmd_alert_to_gui(self, content, packet, identity:IdentityObject = None):
        """
        Dispatches a formatted alert to a connected GUI client.

        This is an internal command handler that acts as a bridge between
        an incoming alert packet and the WebSocket broadcast mechanism.
        """
        self.log(f"Dispatching alert to GUI: {content}")
        self.cmd_broadcast(content, packet)

    def cmd_broadcast(self, content, packet, identity:IdentityObject = None):
        """
        Broadcasts a message to all active WebSocket clients.

        This method is the primary mechanism for sending data from the agent
        to connected GUI clients. It serializes the packet, iterates through
        all active connections, and sends the message asynchronously. It also
        handles the removal of any connections that have gone dead.
        """
        try:

            if not hasattr(self, "loop") or self.loop is None:
                self.log("[WS][REFLEX][SKIP] Event loop not ready.")
                return

            if not getattr(self, "websocket_ready", False):
                self.log("[WS][REFLEX][WAITING] Socket not bound.")
                return

            if self.debug.is_enabled():
                self.log(f"[WS][REFLEX]{packet}")

            data = json.dumps(packet, separators=(",", ":"), sort_keys=False)

            dead = []
            for client in self._websocket_clients:
                try:
                    asyncio.run_coroutine_threadsafe(client.send(data), self.loop)
                except Exception:
                    dead.append(client)

            for c in dead:
                self._websocket_clients.discard(c)

            self.log(f"Broadcasted to {len(self._websocket_clients)} clients.")
        except Exception as e:
            self.log(error=e)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()