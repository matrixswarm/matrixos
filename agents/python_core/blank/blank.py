import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        self.name = "BlankAgent"

    def pre_boot(self):
        self.log("[BLANK] Pre-boot checks complete.")

    def post_boot(self):
        self.log("[BLANK] Post-boot ready. Standing by.")

    def worker_pre(self):
        self.log("Boot initialized. Port online, certs verified.")

    def worker(self, config:dict = None, identity:IdentityObject = None):
        self.log("[BLANK] Worker loop alive.")
        print("Guess what time it is?")
        interruptible_sleep(self, 10)

    def worker_post(self):
        self.log("HTTPS interface shutting down. The swarm will feel it.")


if __name__ == "__main__":
    agent = Agent()
    agent.boot()