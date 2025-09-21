#written by ChatGPT 4
from uuid import uuid4
from datetime import datetime
def make_reaper_node(targets=None,
                     mission_name=None,
                     tombstone_comm=True,
                     tombstone_pod=True,
                     delay=0,
                     cleanup_die=False,
                     is_mission=False):
    uid = uuid4().hex[:6]
    universal_id = mission_name or f"reaper-strike-{uid}"

    config = {
        "tombstone_comm": tombstone_comm,
        "tombstone_pod": tombstone_pod,
        "delay": int(delay),
        "cleanup_die": bool(cleanup_die),
        "created": datetime.now().strftime("%Y%m%d%H%M%S"),
        "is_mission": bool(is_mission),
    }

    if targets:
        config["kill_list"] = targets

    node = {
        "universal_id": universal_id,
        "name": "reaper",
        "config": config
    }

    return node