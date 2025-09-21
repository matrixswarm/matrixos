import os
import re

def clean_old_boots(universe_id="ai", keep_latest=1):
    """
    Cleans up old swarm boot directories under /matrix/{universe_id}/
    except for the most recent one (linked via 'latest').

    :param universe_id: The swarm universe to clean (e.g., "ai", "bb", "os")
    :param keep_latest: Number of most recent boots to preserve
    """
    base_path = os.path.join("/matrix", universe_id)
    if not os.path.exists(base_path):
        print(f"[SWARM-CLEANER][ERROR] Universe path missing: {base_path}")
        return

    latest_real = os.path.realpath(os.path.join(base_path, "latest"))

    def is_boot_dir(name):
        return re.match(r"\d{8}_\d{6}", name)

    all_boots = sorted(
        [d for d in os.listdir(base_path) if is_boot_dir(d)],
        reverse=True
    )

    preserved = all_boots[:keep_latest]

    for folder in all_boots:
        full_path = os.path.join(base_path, folder)
        if folder not in preserved and os.path.realpath(full_path) != latest_real:
            print(f"[SWARM-CLEANER] Removing stale boot: {folder}")
            os.system(f"rm -rf '{full_path}'")