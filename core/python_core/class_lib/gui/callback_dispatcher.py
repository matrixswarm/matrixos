
import time
from core.python_core.utils.crypto_utils import encrypt_with_ephemeral_aes, sign_data


class CallbackCtx:
    """Structured context for secure callback dispatch."""

    def __init__(
        self,
        agent=None,
        rpc_role=None,
        signing_key=None,
        remote_pub_pem=None,
        serial=None,
        origin=None,
        response_handler=None,
        confirm_response=False,
        session_id=None,
        token=None,
    ):
        self._agent = agent
        self._rpc_role = rpc_role or (agent.tree_node.get("rpc_role") if agent else None)
        self._signing_key = signing_key or (getattr(agent, "_signing_key_obj", None))
        self._remote_pub_pem = remote_pub_pem or (getattr(agent, "_signing_keys", {}).get("remote_pubkey") if agent else None)
        self._serial = serial or (getattr(agent, "_serial_num", None))
        self._origin = origin or (getattr(agent, "command_line_args", {}).get("universal_id") if agent else None)
        self._response_handler = response_handler
        self._confirm_response = bool(confirm_response)
        self._session_id = session_id
        self._token = token

    # === Setters ===
    def set_rpc_role(self, role: str): self._rpc_role = role; return self
    def set_signing_key(self, key): self._signing_key = key; return self
    def set_remote_pubkey(self, pem): self._remote_pub_pem = pem; return self
    def set_serial(self, serial): self._serial = serial; return self
    def set_origin(self, origin): self._origin = origin; return self
    def set_response_handler(self, handler): self._response_handler = handler; return self
    def set_confirm_response(self, confirm: bool): self._confirm_response = bool(confirm); return self
    def set_session_id(self, sid): self._session_id = sid; return self
    def set_token(self, token): self._token = token; return self

    # === Getters ===
    def get_rpc_role(self): return self._rpc_role
    def get_signing_key(self): return self._signing_key
    def get_remote_pubkey(self): return self._remote_pub_pem
    def get_serial(self): return self._serial
    def get_origin(self): return self._origin
    def get_response_handler(self): return self._response_handler
    def get_session_id(self): return self._session_id
    def get_token(self): return self._token

    # === Boolean checks ===
    def has_rpc_role(self): return bool(self._rpc_role)
    def has_signing_key(self): return bool(self._signing_key)
    def has_remote_pubkey(self): return bool(self._remote_pub_pem)
    def has_origin(self): return bool(self._origin)
    def has_response_handler(self): return bool(self._response_handler)
    def has_confirm_response(self): return bool(self._confirm_response)
    def is_ready(self):
        return all([self.has_rpc_role(), self.has_signing_key(), self.has_remote_pubkey()])

    def __repr__(self):
        return f"<CallbackCtx rpc_role={self._rpc_role} origin={self._origin} serial={self._serial}>"



class PhoenixCallbackDispatcher:
    """Handles encryption, signing, and delivery of callback responses."""

    def __init__(self, agent):
        self.agent = agent
        self.ctx = None

    def dispatch(self, uid: str, ctx: CallbackCtx = None, content: dict = None):
        """
        Dispatch a secure callback with validated context.
        """
        try:
            context = ctx or self.ctx or CallbackCtx(agent=self.agent)

            # === 1. Context validation ===
            if not context.has_rpc_role():
                self.agent.log("[CALLBACK] rpc_role missing — aborting dispatch.")
                return
            if not context.has_confirm_response():
                self.agent.log("[CALLBACK] confirm_response=0 — skipping callback.")
                return
            if not isinstance(content, dict) or not content:
                self.agent.log("[CALLBACK] Invalid or empty content — nothing to send.")
                return
            if not context.is_ready():
                self.agent.log("[CALLBACK] Incomplete context — missing crypto or role data.")
                return

            rpc_role = context.get_rpc_role()
            signing_key = context.get_signing_key()
            remote_pub_pem = context.get_remote_pubkey()
            serial = context.get_serial()
            origin = context.get_origin()
            handler = context.get_response_handler()
            session_id = context.get_session_id()
            token = context.get_token()

            # === 2. Find endpoints ===
            endpoints = self.agent.get_nodes_by_role(rpc_role, return_count=1)
            if not endpoints:
                self.agent.log(f"[CALLBACK] No endpoints found for rpc_role='{rpc_role}'.")
                return

            # === 3. Encrypt + Sign ===
            payload = {"handler": handler, "content": content}
            sealed = encrypt_with_ephemeral_aes(payload, remote_pub_pem)
            wrapper = {
                "serial": serial,
                "content": sealed,
                "timestamp": int(time.time()),
            }
            wrapper["sig"] = sign_data(wrapper, signing_key)

            pk = self.agent.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": "dummy_handler",
                "origin": origin,
                "session_id": session_id,
                "content": wrapper,
                "token": token,
            })

            # === 4. Send ===
            for ep in endpoints:
                pk.set_payload_item("handler", ep.get_handler())
                self.agent.pass_packet(pk, ep.get_universal_id())

            self.agent.log(f"[CALLBACK] ✅ Callback dispatched to {rpc_role} (uid={uid})")

        except Exception as e:
            self.agent.log(f"[CALLBACK][ERROR] Dispatch failed: {e}")
