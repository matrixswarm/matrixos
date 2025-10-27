import os, subprocess, time, re
from log_watcher.factory.utility.parse_results import parse_results

def collect(cfg=None):
    cfg = cfg or {}
    paths = cfg.get("paths", ["/var/log/maillog"])
    rotate_depth = cfg.get("rotate_depth", 1)
    max_lines = cfg.get("max_lines", 500)
    results = []

    for path in paths:
        try:
            for i in range(rotate_depth + 1):
                suffix = "" if i == 0 else f"-{time.strftime('%Y%m%d', time.localtime(time.time() - i*86400))}"
                file_path = f"{path}{suffix}"
                if not os.path.exists(file_path):
                    continue
                out = subprocess.run(["tail", "-n", str(max_lines), file_path],
                                     capture_output=True, text=True, timeout=5).stdout
                results.extend(out.splitlines())
        except Exception as e:
            results.append(f"[collector error: {e}]")

    filtered = []
    for l in results:
        if re.search(r"status=bounced", l):
            filtered.append(f"[ERROR][BOUNCE] {l}")
        elif re.search(r"status=deferred", l):
            filtered.append(f"[WARNING][DEFERRED] {l}")
        elif re.search(r"status=sent", l):
            filtered.append(f"[NOTICE][SENT] {l}")
    return parse_results(filtered)
