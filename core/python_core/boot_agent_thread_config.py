from thread_timeouts import get_thread_timeout
def get_default_thread_registry():
    return {
        "worker": {"active": False, "timeout": get_thread_timeout("worker")},
        "packet_listener": {"active": False, "timeout": get_thread_timeout("packet_listener")},
        "spawn_manager": {"active": False, "timeout": get_thread_timeout("spawn_manager")},
        "enforce_singleton": {"active": False, "timeout": get_thread_timeout("enforce_singleton")},
        "heartbeat": {"active": False, "timeout": get_thread_timeout("heartbeat")}
    }

def get_thread_timeout_by_name(name):
    defaults = get_default_thread_registry()
    return defaults.get(name, {}).get("timeout", 8)