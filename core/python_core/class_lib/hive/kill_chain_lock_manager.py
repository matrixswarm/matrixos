# kill_chain_lock_manager.py
import os
import sys
import shutil

from core.python_core.tree_parser import TreeParser

class KillChainLockManager:
    """
    Manages locking, freezing, and kill confirmations
    for MatrixSwarm kill operations.
    """

    def __init__(self, tree_parser_obj):
        self.tp = tree_parser_obj

    def lock_targets(self, kill_list):
        for universal_id in kill_list:
            node = self.tp.nodes.get(universal_id)
            if not node:
                print(f"[LOCK] Could not find node {universal_id}! Skipping.")
                continue

            print(f"[LOCK] Marking {universal_id} as operation_in_progress.")
            node["operation_in_progress"] = True

            parent = self.find_parent_of_node(universal_id)
            if not parent:
                print(f"[LOCK] No parent found for {universal_id}. Skipping prune.")
                continue  # 🚨 Don't try to prune if no parent

            if "children" not in parent:
                print(f"[LOCK] Parent of {universal_id} has no children array. Skipping prune.")
                continue

            if parent and "children" in parent:
                before = len(parent["children"])
                original_children = list(parent["children"])  # Make a safe shallow copy
                parent["children"] = [
                    child for child in original_children
                    if isinstance(child, dict) and child.get("universal_id") != universal_id
                ]
                after = len(parent["children"])
                if before != after:
                    print(f"[LOCK] Pruned {before - after} child(ren) from parent of {universal_id}.")

    def find_parent_of_node(self, child_universal_id):
        def recurse(node):
            if not node or not isinstance(node, dict):
                return None
            for child in node.get("children", []):
                if not isinstance(child, dict):
                    continue
                if child.get("universal_id") == child_universal_id:
                    return node
                result = recurse(child)
                if result:
                    return result
            return None

        return recurse(self.tp.root)

    def confirm_deaths(self, kill_list):
        """
        Mark frozen nodes as permanently killed after Reaper success.
        """
        for universal_id in kill_list:
            node = self.tp.nodes.get(universal_id)
            if node:
                node.pop("operation_in_progress", None)
                node["killed"] = True

        self.tp.save_tree(self.tree_path)
        print(f"[KILL-CHAIN] Confirmed deaths for {len(kill_list)} target nodes.")

    def release_locks(self, kill_list):
        """
        Optional: Release locks without marking as killed (abort/recovery protocol).
        """
        for universal_id in kill_list:
            node = self.tp.nodes.get(universal_id)
            if node:
                node.pop("operation_in_progress", None)

        self.tp.save_tree(self.tree_path)
        print(f"[KILL-CHAIN] Released locks for {len(kill_list)} target nodes (no kill confirmed).")

    def refresh(self):
        """
        Reloads the tree parser fresh from disk.
        Useful after another agent modifies the tree.
        """
        self.tp = TreeParser.load_tree(self.tree_path)
