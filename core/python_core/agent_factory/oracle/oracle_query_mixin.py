# Authored by Daniel F MacDonald and ChatGPT 5.2 aka The Generals
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class OracleQuery:
    """
    Lightweight query descriptor used with OracleQueryMixin.

    You normally get one from agent.get_oracle_query_object(), then:
      • set messages
      • set response_handler (name of method on the agent)
      • optionally override oracle_role / rpc_role
      • use save_data() to stash context for the response handler
    """
    query_id: str
    oracle_role: str = "hive.oracle"
    rpc_role: str = "hive.rpc"
    json_response: bool = False
    response_handler: Optional[str] = None  # name of method on the agent
    timeout_sec: int = 300
    messages: List[Dict[str, Any]] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)  # arbitrary context
    created_at: float = field(default_factory=time.time)

    def add_message(self, role: str, content: str):
        self.messages.append({"role": role, "content": content})
        return self

    def save_data(self, extra: Dict[str, Any]):
        """Merge extra context into this query; available on response."""
        if extra:
            self.data.update(extra)
        return self


class OracleQueryMixin:
    """
    Drop-in mixin providing a standard async Oracle query pattern.

    Exposes 4 methods:

      1) get_oracle_query_object()
         → returns an OracleQuery you can configure (messages, handler, etc.)

      2) send_to_oracle(query: OracleQuery)
         → finds Oracle node(s), sends cmd_msg_prompt, and caches the query
           in self._oracle_queries for timeout / response handling.

      3) cmd_oracle_response(content, packet, identity=None)
         → standard handler you wire on your agent; it reconstructs the
           OracleQuery from the cache and invokes the query.response_handler
           method with (query, response_text, error).

      4) check_oracle_timeouts()
         → sweep method; call from worker() to ensure that every query’s
           handler is called even if Oracle never replies (error="timeout").
    """

    def _ensure_oracle_cache(self):
        if not hasattr(self, "_oracle_queries"):
            self._oracle_queries: Dict[str, OracleQuery] = {}
        if not hasattr(self, "oracle_timeout"):
            # per-agent override is allowed; otherwise default 300s
            self.oracle_timeout: int = 300

    # ----------------------------------------------------------
    # 1) get_oracle_query_object
    # ----------------------------------------------------------
    def get_oracle_query_object(self) -> OracleQuery:
        """
        Create a new OracleQuery with a fresh query_id and sane defaults.

        Caller should:
          • query.response_handler = "my_handler_method"
          • query.add_message("system", "...")
          • query.add_message("user", "...")
          • query.save_data({...})   # optional context for the handler
          • optionally override query.oracle_role / query.rpc_role / timeout_sec
        """
        self._ensure_oracle_cache()
        qid = uuid.uuid4().hex
        return OracleQuery(query_id=qid, timeout_sec=self.oracle_timeout)

    # ----------------------------------------------------------
    # 2) send_to_oracle
    # ----------------------------------------------------------
    def send_to_oracle(self, query: OracleQuery):
        """
        Dispatch an OracleQuery to the Oracle agent.

        Guarantees:
          • Raises ValueError if query.response_handler is not set.
          • If Oracle node cannot be found, calls handler immediately
            with error="no_oracle" and does NOT cache the query.
          • On success, stores in self._oracle_queries until either
              - cmd_oracle_response pops it
              - check_oracle_timeouts marks it as timeout.
        """
        self._ensure_oracle_cache()

        if not query.response_handler:
            raise ValueError("OracleQuery.response_handler must be set before send_to_oracle()")

        oracle_nodes = self.get_nodes_by_role(query.oracle_role, return_count=1)
        if not oracle_nodes:
            # no Oracle; call handler immediately with error condition
            handler = getattr(self, query.response_handler, None)
            if handler:
                handler(query, response=None, error="no_oracle")
            else:
                self.log(f"[ORACLE-MIXIN] No Oracle node and handler '{query.response_handler}' not found.",
                         level="ERROR")
            return

        oracle = oracle_nodes[0]

        content = {
            "messages": query.messages,
            "query_id": query.query_id,
            "return_handler": "cmd_oracle_response",
            "session_id": self.command_line_args.get("universal_id"),
            "token": query.query_id,
            "rpc_role": query.rpc_role,
            "json_response": bool(query.json_response),
            "target_universal_id": self.command_line_args.get("universal_id"),
        }

        pk = self.get_delivery_packet("standard.command.packet")
        pk.set_data({
            "handler": "cmd_msg_prompt",
            "timestamp": int(time.time()),
            "content": content,
        })

        try:
            self.pass_packet(pk, oracle.get_universal_id())
        except Exception as e:
            # send failure – call handler immediately
            handler = getattr(self, query.response_handler, None)
            if handler:
                handler(query, response=None, error=str(e) or "send_failed")
            else:
                self.log(f"[ORACLE-MIXIN] Send to Oracle failed and handler '{query.response_handler}' "
                         f"not found: {e}", error=e, level="ERROR")
            return

        # success: cache the query for later response or timeout
        self._oracle_queries[query.query_id] = query
        self.log(f"[ORACLE-MIXIN] Sent query {query.query_id} → {oracle.get_universal_id()}")

    # ----------------------------------------------------------
    # 3) cmd_oracle_response
    # ----------------------------------------------------------
    def cmd_oracle_response(self, content, packet, identity=None):
        """
        Standard callback from Oracle.

        Rebuilds the OracleQuery from cache and invokes the registered handler:

            handler(query, response_text, error)

        Where:
            • query     = OracleQuery (with .data, messages, etc.)
            • response  = str | None
            • error     = None on success, or a string on failure
        """
        try:
            self._ensure_oracle_cache()
            query_id = content.get("query_id") or content.get("content", {}).get("query_id")
            response_text = content.get("response") or content.get("content", {}).get("response")

            self.log(f"[ORACLE-MIXIN] cmd_oracle_response for {query_id}")

            query = self._oracle_queries.pop(query_id, None)
            if not query:
                self.log(f"[ORACLE-MIXIN][WARN] No pending query found for query_id={query_id}")
                return

            handler = getattr(self, query.response_handler, None)
            if not handler:
                self.log(f"[ORACLE-MIXIN][ERROR] Handler '{query.response_handler}' not found on agent.",
                         level="ERROR")
                return

            # Normal success path
            handler(query, response_text, error=None)

        except Exception as e:
            self.log(error=e, block="cmd_oracle_response", level="ERROR")

    # ----------------------------------------------------------
    # 4) check_oracle_timeouts
    # ----------------------------------------------------------
    def check_oracle_timeouts(self):
        """
        Sweep pending Oracle queries and mark timeouts.

        Should be called periodically (e.g. from worker()).
        For each expired query, the registered handler is called with:

            handler(query, response=None, error="timeout")
        """
        try:
            self._ensure_oracle_cache()
            if not self._oracle_queries:
                return

            now = time.time()
            expired_ids = [
                qid for qid, q in self._oracle_queries.items()
                if now - q.created_at > q.timeout_sec
            ]

            for qid in expired_ids:
                query = self._oracle_queries.pop(qid, None)
                if not query:
                    continue
                handler = getattr(self, query.response_handler, None)
                if handler:
                    self.log(f"[ORACLE-MIXIN] Timeout for query {qid}, calling handler.")
                    handler(query, response=None, error="timeout")
                else:
                    self.log(f"[ORACLE-MIXIN][WARN] Timeout for {qid} but handler "
                             f"'{query.response_handler}' not found.")

        except Exception as e:
            self.log(error=e, block="check_oracle_timeouts", level="ERROR")

