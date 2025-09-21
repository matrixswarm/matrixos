import time
import json
import os
from mailman_stream_server import log_to_mailman

class CommandValidator:
    def __init__(self, tree_parser, tree_path):
        self.tree = tree_parser
        self.tree_path = tree_path
        self.queue = []
        self.history = []

    def enqueue(self, command):
        command['timestamp'] = time.time()
        self.queue.append(command)

    def process_next(self):
        if not self.queue:
            return

        command = self.queue.pop(0)
        cmd_type = command.get("type")
        target = command.get("target")

        if cmd_type == "add_node":
            parent = command.get("parent")
            try:
                self.tree.insert_node(command["node"], parent)
                self.tree.mark_confirmed(target)
                self.tree.save_tree(self.tree_path)
                self.history.append(command)
            except ValueError as e:
                log_to_mailman(target, "error", f"[TREE-CONFLICT] {e}")

        elif cmd_type == "delete_node":
            if target in self.tree.nodes:
                del self.tree.nodes[target]
                self.tree.save_tree(self.tree_path)
                self.history.append(command)
            else:
                log_to_mailman(target, "warn", f"[TREE-WARNING] Tried to delete nonexistent node: {target}")

        elif cmd_type == "confirm_node":
            if self.tree.mark_confirmed(target):
                self.tree.save_tree(self.tree_path)
                self.history.append(command)
            else:
                log_to_mailman(target, "warn", f"[TREE-WARNING] Tried to confirm unknown node: {target}")

    def flush(self):
        while self.queue:
            self.process_next()
