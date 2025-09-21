class ServiceEndpoint:
    """
    Wrapper for a service-manager role/handler mapping.
    Provides safe accessors even if the underlying dict is empty or malformed.
    """

    def __init__(self, obj: dict | None = None):
        obj = obj or {}
        self._role = obj.get("role")
        self._handler = obj.get("handler", None)
        self._uid = obj.get("universal_id")

    def is_clear(self)-> bool:
        return self.has_role() and self.has_handler()

    def has_role(self) -> bool:
        """Return True if this endpoint has a role name."""
        return bool(self._role)

    def has_handler(self) -> bool:
        """Return True if this endpoint has a handler name."""
        return bool(self._handler)

    def get_role(self) -> str | None:
        """Return the role string (e.g., 'hive.log') or None."""
        return self._role

    def get_handler(self) -> str | None:
        """Return the handler string (e.g., 'cmd_stream_log') or None."""
        return self._handler

    def get_universal_id(self) -> str | None:
        """Return the universal_id of the agent, or None if absent."""
        return self._uid

    def __repr__(self) -> str:
        return f"<ServiceEndpoint role={self._role} handler={self._handler} uid={self._uid}>"
