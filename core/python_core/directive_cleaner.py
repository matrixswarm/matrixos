import os
import json
from collections import defaultdict

class DirectiveCleaner:
    def __init__(self, directive_path):
        self.directive_path = directive_path
        self.cleaned_tree = {}

    def load(self):
        try:
            with open(self.directive_path, "r", encoding="utf-8") as f:
                self.tree = json.load(f)
            return True
        except Exception as e:
            print(f"[CLEANER] Failed to load directive: {e}")
            self.tree = {}
            return False

    def deduplicate(self):
        # Ensure one entry per universal_id
        seen = {}
        unique_entries = []

        for entry in self.tree.get("agents", []):
            universal_id = entry.get("universal_id")
            if universal_id and universal_id not in seen:
                seen[universal_id] = entry
                unique_entries.append(entry)
            else:
                print(f"[CLEANER] Removing duplicate for universal_id: {universal_id}")

        self.cleaned_tree = {"agents": unique_entries}

    def save(self):
        try:
            with open(self.directive_path, "w", encoding="utf-8") as f:
                json.dump(self.cleaned_tree, f, indent=4)
            print("[CLEANER] Book of Life cleaned and saved.")
        except Exception as e:
            print(f"[CLEANER] Failed to save cleaned directive: {e}")
