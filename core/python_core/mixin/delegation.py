import os
import json
class DelegationMixin:
    def process_update_delegates(self, command):
        self.log("[COMMAND] Delegate update received. Saving tree and spawning.")
        tree_path = os.path.join(
            self.path_resolution["comm_path"],
            self.command_line_args["universal_id"],
            "agent_tree.json"
        )
        with open(tree_path, "w", encoding="utf-8") as f:
            json.dump(command["tree_snapshot"], f, indent=2)
        self.spawn_manager()