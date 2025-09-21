#written by ChatGPT 4
# core/agent_factory/scavenger/scavenger_factory.py
from uuid import uuid4
from datetime import datetime

def make_scavenger_node(tracked_agents=None,  mission_name=None, archive_comm=True, archive_pod=True):

    uid = uuid4().hex[:6]
    mission_id = mission_name or f"scavenger-{uid}"

    config = {
            "archive_comm": archive_comm,
            "archive_pod": archive_pod,
            "created": datetime.now().strftime("%Y%m%d%H%M%S")
        }

    if tracked_agents:
        config["tracked_agents"] = tracked_agents

    return {
        "universal_id": mission_id,
        "name": "scavenger",
        "filesystem": { "folders": [] },
        "config": config,
    }
