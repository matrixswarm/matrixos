class BootDirectiveInfo:
    """
    Wrapper for boot directive metadata passed via security_box.
    Provides safe accessors and formatted debug output.
    """

    def __init__(self, box: dict | None = None):
        box = box or {}

        self._path = box.get("boot_directives_path")     # /some/path/to/directive/.matrixswarm / boot_directives
        self._filename = box.get("boot_directive_filename")      #e.g. .matrixswarm/boot_directives/phoenix-01.enc.json
        self._encrypted = bool(box.get("boot_directive_encrypted")) #e.g. TRUE|FALSE
        self._swarm_key = box.get("boot_directive_swarm_key")      #e.g. DwoQXA3V14t6yEe3rEe53StT2rhtU9PjXHFF7RRxys4=

    def get_path(self) -> str | None:
        """Absolute path to the boot_directives directory."""
        return self._path

    def get_filename(self) -> str | None:
        """Name of the directive file (json, py, or enc.json)."""
        return self._filename

    def is_encrypted(self) -> bool:
        """True if the directive was loaded from an encrypted file."""
        return self._encrypted

    def get_swarm_key(self) -> str | None:
        """Base64 swarm key used for decrypting the directive (if encrypted)."""
        return self._swarm_key

    def is_clear(self) -> bool:
        """Return True if both path and filename are present."""
        return bool(self._path and self._filename)

    def __repr__(self) -> str:
        return (f"<BootDirectiveInfo path={self._path} "
                f"file={self._filename} "
                f"encrypted={self._encrypted} "
                f"swarm_key={'set' if self._swarm_key else 'None'}>")
