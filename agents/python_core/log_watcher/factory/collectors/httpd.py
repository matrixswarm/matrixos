# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import subprocess, time, os
from log_watcher.factory.utility.parse_results import parse_results

def collect(cfg=None):
    cfg = cfg or {}
    paths = cfg.get("paths", ["/var/log/httpd/error_log"])
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
                cmd = ["tail", "-n", str(max_lines), file_path]
                out = subprocess.run(cmd, capture_output=True, text=True).stdout
                results.extend(out.splitlines())
        except Exception as e:
            results.append(f"[collector error: {e}]")

    return parse_results(results)

