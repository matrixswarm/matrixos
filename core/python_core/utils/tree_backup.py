import os
import shutil
import json
from datetime import datetime

def backup_agent_tree(tree_path, backup_dir=None, replaced_node_id=None, new_node_id=None):
    if not os.path.exists(tree_path):
        print(f"[TREE-BACKUP] No tree found at: {tree_path}")
        return

    with open(tree_path, "r", encoding="utf-8") as f:
        try:
            archived_tree = json.load(f)
        except Exception as e:
            print(f"[TREE-BACKUP][ERROR] Failed to load tree for backup: {e}")
            return

    if replaced_node_id and replaced_node_id in archived_tree.get("nodes", {}):
        archived_tree["nodes"][replaced_node_id]["replaced_by"] = new_node_id
        archived_tree["nodes"][replaced_node_id]["replaced_at"] = datetime.utcnow().isoformat()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"agent_tree_master_backup_{timestamp}.json"

    if backup_dir:
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, filename)
    else:
        backup_path = tree_path.replace("agent_tree_master.json", filename)

    try:


        with open(backup_path, "w", encoding="utf-8") as f:
            json.dump(archived_tree, f, indent=2)



        print(f"[TREE-BACKUP] Snapshot saved to: {backup_path}")
    except Exception as e:
        print(f"[TREE-BACKUP][ERROR] Failed to write backup: {e}")
