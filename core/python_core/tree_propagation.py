def propagate_tree_slice(tree_parser, target_universal_id, comm_path):
    """
    Pushes an update_delegates.cmd file to the specified agent's incoming folder.
    """
    import json
    import time
    import os

    subtree = tree_parser.extract_subtree_by_id(target_universal_id)
    if not subtree:
        print(f"[PROPAGATION] No subtree found for {target_universal_id}")
        return False

    payload = {
        "action": "update_delegates",
        "delegated": [child["universal_id"] for child in subtree.get("children", [])],
        "tree_snapshot": subtree,
        "timestamp": int(time.time())
    }

    incoming_path = os.path.join(comm_path, target_universal_id, "incoming")
    os.makedirs(incoming_path, exist_ok=True)

    filename = f"update_delegates_{payload['timestamp']}.cmd"
    full_path = os.path.join(incoming_path, filename)

    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"[PROPAGATION] Pushed delegate update to {target_universal_id}")
    return True
