# Authored by Daniel F MacDonald and ChatGPT aka The Generals
from uuid import uuid4
from datetime import datetime
def make_reaper_node(universal_id):

    config = {
        "ui": {
            "agent_tree": {"emoji": "💀"},
        },
    }

    node = {
        "universal_id": universal_id,
        "name": "reaper",
        "config": config
    }

    return node