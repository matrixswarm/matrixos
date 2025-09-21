import os
import time
from matrixswarm.agent.core.python_core.boot_agent import BootAgent
from matrixswarm.agent.core.python_core.utils.swarm_sleep import interruptible_sleep

class BlankAgent(BootAgent):
    def __init__(self, path_resolution, command_line_args, tree_node=None):
        super().__init__(path_resolution, command_line_args, tree_node=tree_node)
        self.name = "BlankAgent"

    def pre_boot(self):
        self.log("[BLANK] Pre-boot checks complete.")

    def post_boot(self):
        self.log("[BLANK] Post-boot ready. Standing by.")

    def worker(self):
        self.log("[BLANK] Worker loop alive.")
        interruptible_sleep(self, 10)

if __name__ == "__main__":
    path_resolution["pod_path_resolved"] = os.path.dirname(os.path.abspath(__file__))
    agent = BlankAgent(path_resolution, command_line_args)
    agent.boot()