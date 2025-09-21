import os
import json
import time
from core.python_core.tree_parser import TreeParser
from core.python_core.tree_propagation import propagate_tree_slice

class TreeDisseminator:
    def __init__(self, tree_path, comm_path):
        self.tree_path = tree_path
        self.comm_path = comm_path
        self.last_snapshot = {}

    def load_tree(self):
        tp = TreeParser.load_tree(self.tree_path)
        if not tp:
            print(f"[TREE-DISSEMINATOR] Failed to load tree: {self.tree_path}")
            return None
        return tp

    def disseminate_all(self):
        tp = self.load_tree()
        if not tp:
            return False

        top_node_id = tp.root.get("universal_id")
        if not top_node_id:
            print("[TREE-DISSEMINATOR] Root node missing universal_id.")
            return False

        delegated = tp.query_children_by_id(top_node_id)
        for universal_id in delegated:
            print(f"[TREE-DISSEMINATOR] Disseminating to: {universal_id}")
            propagate_tree_slice(tp, universal_id, self.comm_path)
        return True

    def disseminate_if_changed(self):
        try:
            mtime = os.path.getmtime(self.tree_path)
            if self.last_snapshot.get("mtime") != mtime:
                print("[TREE-DISSEMINATOR] Tree changed. Disseminating...")
                self.disseminate_all()
                self.last_snapshot["mtime"] = mtime
        except Exception as e:
            print(f"[TREE-DISSEMINATOR] Failed mtime check: {e}")
