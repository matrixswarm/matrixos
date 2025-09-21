# core/thread_timeouts.py

# Default timeouts for known thread types (in seconds)
DEFAULT_THREAD_TIMEOUTS = {
    "worker": 10,
    "cmd_listener": 6,
    "reflex_listener": 6,
    "spawn_manager": 12,
    "enforce_singleton": 10,
    "heartbeat": 10
}

# Runtime override cache (modifiable during agent runtime)
thread_timeout_overrides = {}

def get_thread_timeout(thread_name):
    """
    Returns the timeout value for a thread. Uses runtime override if set.
    """
    return thread_timeout_overrides.get(thread_name, DEFAULT_THREAD_TIMEOUTS.get(thread_name, 8))

def set_thread_timeout(thread_name, timeout):
    """
    Override timeout for a specific thread during runtime.
    """
    thread_timeout_overrides[thread_name] = timeout

def list_all_defaults():
    """
    Returns a copy of the default thread timeout map.
    """
    return dict(DEFAULT_THREAD_TIMEOUTS)

def list_active_overrides():
    """
    Returns currently overridden timeouts.
    """
    return dict(thread_timeout_overrides)