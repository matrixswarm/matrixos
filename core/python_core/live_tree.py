import json
import os

class LiveTree:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LiveTree, cls).__new__(cls)
            cls._instance.data = {}
            cls._instance.path = None
        return cls._instance

    def load(self, path):
        self.path = path
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        else:
            self.data = {}
        print(f"[TREE] Loaded tree from: {path}")

    def save(self):
        if self.path:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            print(f"[TREE] Saved tree to: {self.path}")

    def get_delegates(self, universal_id):
        return self.data.get(universal_id, [])

    def inject(self, universal_id, delegated):
        self.data[universal_id] = delegated
        print(f"[TREE] Injected: {universal_id} → {delegated}")
        self.save()

    def delete_node(self, universal_id):
        if universal_id in self.data:
            del self.data[universal_id]
            print(f"[TREE] Deleted node: {universal_id}")
            self.save()

    def delete_subtree(self, root):
        removed = []
        def recurse(p):
            children = self.data.get(p, [])
            for c in children:
                recurse(c)
            if p in self.data:
                del self.data[p]
                removed.append(p)
        recurse(root)
        print(f"[TREE] Deleted subtree: {removed}")
        self.save()
