# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini, code enhancements and Docstrings
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
from flask import Response
from flask import Flask, request, jsonify
import threading
import time
import ssl
from Crypto.PublicKey import RSA
from werkzeug.serving import WSGIRequestHandler
from core.python_core.utils.cert_loader import load_cert_chain_from_memory
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_trustkit import extract_spki_pin_from_cert
from core.python_core.class_lib.packet_delivery.utility.security.packet_size import guard_packet_size
from core.python_core.utils import crypto_utils
from core.python_core.utils.swarm_sleep import interruptible_sleep
from werkzeug.serving import make_server
from core.python_core.utils.crypto_utils import encrypt_with_ephemeral_aes,  sign_data, pem_fix
class CustomRequestHandler(WSGIRequestHandler):
    """
    A custom WSGI request handler that retrieves the client's TLS certificate.

    This handler is used by the Flask server to access the binary form of the
    peer's certificate. It overrides the standard `make_environ` method to
    add the certificate data to the request's environment dictionary, making
    it available to the application's routes for mutual TLS authentication.
    """
    def make_environ(self):
        """
        Creates the WSGI environment dictionary for the request.

        This method is a core part of the WSGI standard. It is overridden here
        to attach the client's certificate as a binary object to the environment
        under the key "peercert".

        Returns:
            dict: The standard WSGI environment dictionary, with the addition of
                  the "peercert" key if a client certificate is present.
        """
        environ = super().make_environ()
        try:
            client_cert = self.connection.getpeercert(binary_form=True)
            environ["peercert"] = client_cert
        except Exception:
            environ["peercert"] = None
        return environ

class Agent(BootAgent):
    """
    The Matrix HTTPS Agent, a specialized BootAgent for secure,
    packet-based communication over HTTPS.

    This agent extends the core functionality of a BootAgent with a Flask-based
    HTTPS server. It is designed to act as a secure ingress point for
    external commands, enforcing multiple layers of authentication, including
    mutual TLS (mTLS) with SPKI pin verification and a cryptographic signature
    check on the packet payload.

    It also includes endpoints to trap and log unauthorized access attempts.

    Attributes:
        AGENT_VERSION (str): The version of the agent.
        app (Flask.app): The Flask application instance that runs the HTTPS server.
        port (int): The network port the server listens on.
        allowlist_ips (list): A list of IP addresses permitted to access the server.
        payload_dir (str): The filesystem path for storing incoming packet payloads.
        cert_pem (str): The agent's TLS certificate in PEM format.
        key_pem (str): The agent's private key in PEM format.
        ca_pem (str): The PEM-encoded CA root certificate for client verification.
        local_spki (str): The SHA-256 SPKI fingerprint of the agent's server cert.
        expected_peer_spki (str): The expected SPKI pin of the connecting client.
        peer_pub_key (Crypto.PublicKey.RSA): The public key used to verify
            signatures on incoming packets.
        run_server_retries (bool): A flag to control server restart attempts.
        _emit_process_beacon (function): A beacon function to signal process liveness.
        _emit_beacon (function): A beacon function to signal service liveness.

    Methods:
        pre_boot():
            Initializes and starts the HTTPS server thread before the main
            agent loops begin.

        post_boot():
            Logs a message indicating the agent is fully operational.

        process_command(data):
            A placeholder method for processing delegated commands.

        worker_pre():
            A hook that runs once before the main worker loop.

        service_monitor():
            Continuously pings the local server to verify the health of the
            HTTPS stack, emitting a liveness beacon on success.

        worker_post():
            A hook that runs once after the main worker loop exits.

        configure_routes():
            Sets up all Flask routes for the server, including the main
            `/matrix` endpoint, and various trap/denial endpoints.

        receive_command():
            The main POST handler for the `/matrix` endpoint. It performs
            a multi-step security check on incoming requests:
            1.  IP allowlist verification.
            2.  Mutual TLS SPKI pin verification.
            3.  JSON payload parsing and size guard.
            4.  Timestamp-based replay attack prevention.
            5.  Cryptographic signature verification on the payload.
            If all checks pass, the packet is relayed to the core Matrix agent.

        deny_unsupported_methods():
            A handler that traps and logs requests using unsupported HTTP
            methods on the `/matrix` endpoint.

        trap_scan_targets():
            A handler for decoy endpoints that logs and denies requests to
            common attack targets like `/robots.txt` or `/wp-login.php`.

        make_spoof_response():
            Generates a deceptive HTML response to mislead automated scanners.

        shutdown_cleanup():
            Deletes temporary certificate files created during server startup.

        run_server():
            Initializes and runs the HTTPS server with mutual TLS, handling
            potential startup failures with retries.

        """
    def __init__(self):
        super().__init__()
        """
        Initializes the Matrix HTTPS agent.

        It first calls the parent `BootAgent` constructor, then securely
        loads TLS certificates and keys from the agent's directive. It
        configures the Flask application and its routes, preparing the
        HTTPS server for operation.
        """
        self.AGENT_VERSION = "2.0.0"
        self.app = Flask(__name__)
        self.port = 65431

        try:

            config = self.tree_node.get("config", {})
            self.allowlist_ips = config.get("allowlist_ips", [])

            self.payload_dir = os.path.join(self.path_resolution['comm_path'], "matrix", "payload")

            security = config.get("security", {}) or {}
            conn = security.get("connection", {}) or {}

            server_cert = conn.get("server_cert", {}) or {}
            client_cert = conn.get("client_cert", {}) or {}
            ca_root = conn.get("ca_root", {}) or {}

            # Load our server TLS cert & key
            cert_pem = server_cert.get("cert")
            key_pem = server_cert.get("key")
            ca_pem = ca_root.get("cert")

            if not cert_pem or not key_pem:
                raise ValueError("Missing server TLS cert/key in connection.server_cert")

            # Store in-memory PEMs
            self.cert_pem = pem_fix(cert_pem)
            self.key_pem = pem_fix(key_pem)
            self.ca_pem = pem_fix(ca_pem) if ca_pem else None

            # Compute local SPKI pin for diagnostics (optional)
            try:
                self.local_spki = extract_spki_pin_from_cert(self.cert_pem.encode())
            except Exception as e:
                self.local_spki = None
                self.log("[HTTPS][SPKI][WARN] Could not compute local SPKI pin", error=e)

            # Optionally track expected client SPKI pin (not enforced)
            self.expected_peer_spki = client_cert.get("spki_pin")

            # Optionally load remote_pubkey for packet signature auth
            self._signing_keys = security.get("signing", {})
            self._has_signing_keys = bool(self._signing_keys.get('privkey')) and bool(self._signing_keys.get('remote_pubkey'))

            if self._has_signing_keys:
                priv_pem = self._signing_keys.get("privkey")
                priv_pem = pem_fix(priv_pem)
                self._signing_key_obj = RSA.import_key(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)
                self._peer_pub_key = RSA.import_key(self._signing_keys.get("remote_pubkey").encode())

            self.log(f"[SERVER-CERT-DEBUG] uid={self.command_line_args['universal_id']} "
                  f"cert_len={len(cert_pem or '')} "
                  f"key_len={len(key_pem or '')} "
                  f"ca_len={len(ca_pem or '')} "
                  f"spki_pin={self.expected_peer_spki}")

            self.log("[CERT-LOADER] In-memory TLS certs loaded successfully.")
            self.configure_routes()
            # True service liveness
            self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)


        except Exception as e:
            self.log("[CERT-LOADER][FATAL] Failed to load certs from directive", error=e, block="init")
            time.sleep(2)

        self.local_tree_root = None
        # keep trying to start for infinity: false do max retries in method
        self.run_server_retries = False
        self._last_dir_request = 0

    def pre_boot(self):
        """
        A one-time setup hook called before the main threads start.

        This method is overridden to start the HTTPS server in a background
        thread, ensuring the network interface is up and running before the
        rest of the agent's core loops begin.
        """
        self.log("[PRE-BOOT] Matrix HTTPS Agent preparing routes and scanner.")
        threading.Thread(target=self.run_server, daemon=True).start()

    def post_boot(self):
        """
        A one-time setup hook called after the main threads have started.

        This method is overridden to log a confirmation that the agent is
        fully operational and the perimeter guard is in place.
        """
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – perimeter guard up.")

    def process_command(self, data):
        """
        Processes a delegated command.

        This is a placeholder method that would be implemented to handle
        specific commands relayed from the `/matrix` endpoint.
        """
        self.log(f"[CMD] Received delegated command: {data}")

    def worker_pre(self):
        """
        A hook that runs once before the main worker loop.

        This method logs a message confirming that the boot process is
        initialized and the HTTPS interface is online.
        """
        self.log("[MATRIX_HTTPS] Boot initialized. Port online, certs verified.")

    def worker(self, config=None, identity=None):
        """
        Main loop hook for Matrix HTTPS agent.
        This keeps emitting a heartbeat and respects die.cookie / rug_pull.
        """
        if not self.running:
            return

        # emit a liveness beacon so Phoenix sees this agent alive
        self._emit_beacon()

        # Also double-check that the Flask server is still healthy
        try:
            with self.app.test_client() as client:
                resp = client.get("/ping")
                if resp.status_code == 200:
                    self._emit_beacon()
                else:
                    self.log(f"[MATRIX-HTTPS][ERROR] Worker ping unhealthy: {resp.status_code}")
        except Exception as e:
            self.log("[MATRIX-HTTPS][ERROR] Worker ping failed", error=e)

        interruptible_sleep(self, 15)

    def service_monitor(self):
        """
        Continuously self-pings the Flask `/ping` route to prove HTTPS stack health.

        This method runs in a background thread and acts as a liveness check.
        It uses a Flask test client to make a GET request to a local endpoint,
        and if the response is successful, it emits a liveness beacon.
        """
        emit_beacon = self.check_for_thread_poke("service_monitor", timeout=60, emit_to_file_interval=10)
        while self.running:
            try:
                with self.app.test_client() as client:
                    resp = client.get("/ping")
                    if resp.status_code == 200:
                        emit_beacon()
                    else:
                        self.log(f"[MATRIX-HTTPS][ERROR] Ping route unhealthy: {resp.status_code}")
            except Exception as e:
                self.log("[MATRIX-HTTPS][ERROR] Internal ping failed", error=e)

            interruptible_sleep(self, 20)

    def worker_post(self):
        """
        A hook that runs once after the main worker loop exits.

        This method is called during agent shutdown and logs a message
        indicating the HTTPS interface is going down.
        """
        self.log("[MATRIX_HTTPS] HTTPS interface shutting down. The swarm will feel it.")

    def configure_routes(self):
        """
        Sets up and configures all Flask routes for the HTTPS server.

        This method defines the various endpoints the server will respond to,
        including the primary `/matrix` command handler, a `/ping` health check,
        and various decoy endpoints to trap and log malicious scans.
        """
        @self.app.route("/ping", methods=["GET"])
        def ping():
            return jsonify({"status": "ok"}), 200

        @self.app.route("/matrix", methods=["POST"])
        def receive_command():
            """
            Handles incoming POST requests to the `/matrix` endpoint.

            This function performs a series of stringent security checks on the
            request to ensure it is authentic and secure. It verifies the client's
            IP, SPKI pin from the TLS certificate, the packet size, the timestamp
            for freshness, and a cryptographic signature on the payload. If all
            checks pass, it relays the command to the Matrix core agent via the
            internal packet delivery system.

            Returns:
                Flask.Response: A JSON response indicating the status of the
                                request (e.g., "ok", "denied", "error").
            """
            try:

                ip = request.remote_addr or "unknown"

                # 0) IP allowlist gate
                if self.allowlist_ips:
                    if ip not in self.allowlist_ips:
                        self.log(f"[MATRIX-HTTPS][BLOCKED] IP {ip} not in allowlist")
                        return jsonify({"status": "error", "message": "Access denied"}), 403
                    else:
                        self.log(f"[MATRIX-HTTPS][SECURITY] IP {ip} explicitly allowed by allowlist")
                else:
                    self.log("[MATRIX-HTTPS][SECURITY] No IP allowlist restriction in place")

                # 1) TLS client-cert SPKI pin (bind transport to expected peer)
                cert_bin = request.environ.get("peercert", None)
                if not cert_bin or not self.expected_peer_spki:
                    return jsonify({"status": "denied", "message": "missing peer cert or pin"}), 403

                actual_pin = extract_spki_pin_from_cert(cert_bin)
                if actual_pin != self.expected_peer_spki:
                    self.log(f"[HTTPS][SPKI DENY] got {actual_pin}, expected {self.expected_peer_spki}")
                    return jsonify({"status": "denied", "message": "SPKI mismatch"}), 403

                # 2) Parse JSON
                    #inner['inner'] = content
                    #inner["ts"] = int(time.time())
                    #inner["session_id"] = self.session_id
                outer = request.get_json(silent=True, force=True) or {}
                sig_b64 = outer.get("sig")
                inner = outer.get("content")
                matrix_packet=inner.get("matrix_packet")
                ts = inner.get('ts')

                self.log(f"{inner}")

                # 3) Size / structure guard on inner packet
                if not guard_packet_size(matrix_packet, log=self.log):
                    return jsonify({"status": "error", "message": "bad or oversized payload"}), 413

                # 4) Replay window
                try:
                    if not ts or abs(time.time() - float(ts)) > 120:
                        return jsonify({"status": "denied", "message": "stale"}), 403
                except Exception:
                    return jsonify({"status": "denied", "message": "bad timestamp"}), 403

                # 5) Signature verification over inner dict
                if not (self._peer_pub_key and sig_b64 and inner):
                    return jsonify({"status": "denied", "message": "missing signature or key"}), 403

                # 6) Verify Signature
                try:
                    crypto_utils.verify_signed_payload(inner, sig_b64, self._peer_pub_key)
                except Exception as e:
                    self.log(f"[HTTPS][SIG DENY] {e}")
                    return jsonify({"status": "denied", "message": "bad signature"}), 403

                # 7) Packet Integrity
                if not isinstance(matrix_packet, dict):
                    return jsonify({"status": "error", "message": "bad packet format"}), 400

                # 8) All gates passed — relay to Matrix
                self.log(f"[MATRIX-HTTPS][RELAY] cmd_the_source from {ip}")

                pk = self.get_delivery_packet("standard.command.packet", new=True)
                pk.set_data({'handler': "cmd_the_source", "content":matrix_packet})  # relay the verified inner command


                # 9) Forward to Matrix
                self.pass_packet(pk, target_uid="matrix")
                return jsonify({"status": "ok", "message": "Relayed to Matrix"})


            except Exception as e:
                self.log(f"[MATRIX-HTTPS][ERROR]", error=e, block="main_try")
                return jsonify({"status": "error", "message": str(e)}), 500



        @self.app.route("/matrix", methods=["GET", "PUT", "DELETE", "OPTIONS", "HEAD"])
        def deny_unsupported_methods():
            """
            Catches and denies unsupported HTTP methods.

            This handler logs and denies any request to the `/matrix` endpoint
            that is not a POST request, returning a spoofed response to
            harden the server against reconnaissance.
            """
            ip = request.remote_addr or "unknown"
            if self.allowlist_ips:
                if ip not in self.allowlist_ips:
                    self.log(f"[MATRIX-HTTPS][BLOCKED] Request from disallowed IP: {ip}")
                    return jsonify({"status": "error", "message": "Access denied"}), 403
                else:
                    self.log(f"[MATRIX-HTTPS][SECURITY] IP {ip} explicitly allowed by allowlist")
            else:
                self.log("[MATRIX-HTTPS][SECURITY] No IP allowlist restriction in place")

            self.log(f"[MATRIX-HTTPS][TRAP] Got {request.method} from {request.remote_addr}")
            return self.make_spoof_response()

        @self.app.route("/robots.txt", methods=["GET"])
        @self.app.route("/admin", methods=["GET"])
        @self.app.route("/wp-login.php", methods=["GET", "POST"])
        @self.app.route("/cgi-bin/", methods=["GET", "POST"])

        def trap_scan_targets():
            """
            A series of decoy endpoints designed to trap malicious scanning.

            Requests to these common attack targets are logged and denied,
            providing early warning of reconnaissance attempts.
            """
            self.log(f"[MATRIX-HTTPS][SCAN-TRAP] Bait endpoint hit by {request.remote_addr}")
            return self.make_spoof_response()

    #Change this to what you want default apache or nginx page
    def make_spoof_response(self):

        msg = """<!DOCTYPE html>
                           <html>
                           <head>
                             <title>Nice Try</title>
                             <style>
                               body {
                                 background: black;
                                 color: #0f0;
                                 font-family: monospace;
                                 text-align: center;
                                 margin-top: 10vh;
                               }
                             </style>
                           </head>
                           <body>
                             <h1>🧠 Nice one, genius.</h1>
                             <p>This isn't a WordPress blog. It's a swarm fortress.</p>
                             <p>Consider this your official notification: you triggered the trap.</p>
                             <p><small>Matrix has logged your request.</small></p>
                           </body>
                           </html>
                           """
        return Response(msg, status=418, mimetype="text/html")  # 418 I'm a Teapot


    def shutdown_cleanup(self):
        """
        Performs cleanup of temporary files during shutdown.

        This method is called to safely delete any temporary certificate files
        that were created in-memory for the HTTPS server, ensuring no sensitive
        data is left on the filesystem.
        """
        for f in [getattr(self, "_cert_file", None), getattr(self, "_key_file", None), getattr(self, "_ca_file", None)]:
            try:
                if f and hasattr(f, "name") and os.path.exists(f.name):
                    os.unlink(f.name)
                    self.log(f"[CLEANUP] Deleted temp cert file: {f.name}")
            except Exception as e:
                self.log("[CLEANUP][ERROR] Failed to delete temp cert", error=e, block="shutdown")

    def run_server(self):
        """
        Initializes and starts the Flask HTTPS server.

        This method sets up the SSL context for mutual TLS, loads the
        certificates, and begins serving requests. It includes a retry
        mechanism to handle transient startup failures. It also starts
        watchdog threads to monitor the liveness of the process and
        the service.
        """
        retry_delay = 10
        max_retries = 5
        retries = 0

        while (retries < max_retries) or self.run_server_retries:
            try:
                self.log("[HTTPS] Starting run_server()...")

                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                # Require client certs, but don't allow them to stall forever
                context.verify_mode = ssl.CERT_REQUIRED
                load_cert_chain_from_memory(context, self.cert_pem, self.key_pem)

                if self.ca_pem:
                    context.load_verify_locations(cadata=self.ca_pem)

                httpd = make_server(
                    "0.0.0.0",
                    self.port,
                    self.app,
                    ssl_context=context,
                    request_handler=CustomRequestHandler
                )

                # Limit how long handshakes can sit idle
                httpd.socket.settimeout(30)  # 30-second handshake window

                self.log(f"[HTTPS] Listening on port {self.port}")

                # Start process liveness thread
                def process_monitor():
                    emit_beacon = self.check_for_thread_poke("process_monitor", timeout=60, emit_to_file_interval=10)
                    while self.running:
                        emit_beacon()
                        interruptible_sleep(self, 20)

                # Run the HTTPS server loop in its own thread
                threading.Thread(target=httpd.serve_forever, daemon=True).start()

                # Watchdog threads
                threading.Thread(target=process_monitor, daemon=True).start()
                threading.Thread(target=self.service_monitor, daemon=True).start()

                break  # success

            except Exception as e:
                self.log(f"[HTTPS][FAIL] Server failed to start or crashed", error=e)
                retries += 1
                self.log(f"[HTTPS][RETRY] Attempt {retries}/{max_retries} in {retry_delay}s")
                time.sleep(retry_delay)
            finally:
                self.shutdown_cleanup()

        if retries >= max_retries:
            self.log("[HTTPS][ABORT] Max retries reached. Server not started.")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()