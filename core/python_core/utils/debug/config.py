class DebugConfig:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DebugConfig, cls).__new__(cls)

            cls._instance._enabled = False

        return cls._instance

    def set_enabled(self, enabled:bool=True):
        self._enabled=bool(enabled)

    def is_enabled(self) -> bool:
        return self._enabled

DEBUG_CONFIG = DebugConfig()