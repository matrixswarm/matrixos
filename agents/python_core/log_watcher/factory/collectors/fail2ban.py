from log_watcher.factory.utility.parse_results import parse_results
from log_watcher.factory.utility.log_reader import collect_log

def collect(log=None, cfg=None):
    """HTTPD collector — uses shared log reader."""
    result = collect_log(log, cfg)
    # You can extend here: detect mod_cgid errors, missing robots.txt, etc.
    return result