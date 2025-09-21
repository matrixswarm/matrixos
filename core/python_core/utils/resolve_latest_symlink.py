import os
import re

def resolve_latest_symlink(universe):
    matrix_root = os.path.join("/matrix", universe)
    latest_path = os.path.join(matrix_root, "latest")

    # If symlink exists and is valid
    if os.path.islink(latest_path) and os.path.exists(os.readlink(latest_path)):
        print(f"[LATEST] Valid symlink already in place: {latest_path}")
        return True

    print(f"[LATEST] Missing or broken symlink. Attempting recovery...")

    try:
        # Find all reboot UUID folders
        boot_dirs = [
            d for d in os.listdir(matrix_root)
            if re.match(r"\d{8}_\d{6}", d) and os.path.isdir(os.path.join(matrix_root, d))
        ]

        if not boot_dirs:
            print("[LATEST][ERROR] No valid reboot folders found.")
            return False

        # Sort by datetime
        boot_dirs.sort(reverse=True)
        newest = boot_dirs[0]

        # Repair the symlink
        new_target = os.path.join(matrix_root, newest)

        if os.path.exists(latest_path) or os.path.islink(latest_path):
            os.remove(latest_path)

        os.symlink(newest, latest_path)
        print(f"[LATEST] Symlink repaired: {latest_path} → {newest}")
        return True

    except Exception as e:
        print(f"[LATEST][ERROR] Failed to repair symlink: {e}")
        return False