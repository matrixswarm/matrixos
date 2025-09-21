import os

def analyze_spawn_records(comm_root, agent_id, flip_threshold=3, flip_window=60, spawn_dir="spawn"):
    """
    Scans the spawn directory for an agent and analyzes spawn frequency.

    Args:
        spawn_dir (str): Full path to the /spawn folder of an agent.
        flip_threshold (int): Max allowed spawns within flip_window before flagged.
        flip_window (int): Time window (in seconds) to detect flip-tripping.

    Returns:
        dict: {
            "count": total number of spawns,
            "latest_timestamp": most recent timestamp (int),
            "flip_tripping": True if too many spawns in time window
        }
    """
    try:
        spawn_dir = os.path.join(comm_root, agent_id, spawn_dir)
        files = [f for f in os.listdir(spawn_dir) if f.endswith(".spawn")]
        if not files:
            return {"count": 0, "latest_timestamp": None, "flip_tripping": False}

        timestamps = []

        for fname in files:
            try:
                ts_part = fname.split("_")[0]
                ts_int = int(ts_part)
                timestamps.append(ts_int)
            except (ValueError, IndexError):
                continue  # skip malformed filenames

        timestamps.sort()
        total = len(timestamps)
        latest = timestamps[-1]

        # Flip-trip detection: count how many happened in the last flip_window seconds
        recent_flips = [t for t in timestamps if latest - t <= flip_window]
        flip_tripping = len(recent_flips) >= flip_threshold

        return {
            "count": total,
            "latest_timestamp": latest,
            "flip_tripping": flip_tripping
        }

    except Exception as e:
        return {
            "count": 0,
            "latest_timestamp": None,
            "flip_tripping": False,
            "error": str(e)
        }
