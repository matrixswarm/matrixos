# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import os, time
from log_watcher.factory.utility.parse_results import parse_results

def tail_file(path, n=500, block_size=8192):
    """
    True end-of-file tailer.
    Reads the last `n` lines from `path` without pulling the head.
    """
    if not os.path.exists(path):
        return []

    lines = []
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        block_end = file_size
        buffer = b""
        while len(lines) <= n and block_end > 0:
            read_size = min(block_size, block_end)
            block_end -= read_size
            f.seek(block_end)
            buffer = f.read(read_size) + buffer
            lines = buffer.splitlines()

    # decode and return last n lines newest-to-oldest
    return [l.decode("utf-8", errors="ignore") for l in lines[-n:]]

def collect_log(log=None, cfg=None):
    """
    Shared log reader.
    Handles file tailing, in-memory text, or list of lines.
    Returns parsed summary via parse_results().
    """
    cfg = cfg or {}
    max_lines = int(cfg.get("max_lines", 500))
    rotate_depth = int(cfg.get("rotate_depth", 1))
    results = []

    # Direct in-memory log data
    if isinstance(log, list):
        results = log[-max_lines:]
        return parse_results(results)

    if isinstance(log, str) and not os.path.exists(log):
        results = log.splitlines()[-max_lines:]
        return parse_results(results)

    # File or configured paths
    paths = []
    if isinstance(log, str) and os.path.exists(log):
        paths = [log]
    elif cfg.get("paths"):
        paths = cfg["paths"]

    for path in paths:
        for i in range(rotate_depth + 1):
            suffix = "" if i == 0 else f"-{time.strftime('%Y%m%d', time.localtime(time.time() - i*86400))}"
            file_path = f"{path}{suffix}"
            if not os.path.exists(file_path):
                continue
            try:
                # Read from end of file precisely
                results.extend(tail_file(file_path, n=max_lines))
            except Exception as e:
                results.append(f"[collector error: {e}]")

    return parse_results(results)
