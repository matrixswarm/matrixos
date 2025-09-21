import os
import os
import uuid
from datetime import datetime

# 🌌 The root identity of this Matrix swarm instance
UNIVERSE_ID = os.environ.get("UNIVERSE_ID", "bb")  # bb = Big Bang
REBOOT_UUID = os.environ.get("REBOOT_UUID", datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ"))