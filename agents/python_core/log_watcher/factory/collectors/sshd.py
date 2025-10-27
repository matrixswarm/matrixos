# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import subprocess, re, os

def collect(cfg=None):
    cfg = cfg or {}
    paths = cfg.get("paths", ["/var/log/secure", "/var/log/auth.log"])
    rotate_depth = cfg.get("rotate_depth", 0)
    max_lines = cfg.get("max_lines", 500)

    result = {"summary": "", "failed": [], "accepted": [], "keys": [], "invalid": []}

    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            lines = subprocess.run(
                ["tail", "-n", str(max_lines), path],
                capture_output=True, text=True, timeout=5
            ).stdout.splitlines()

            fails = [l for l in lines if re.search(r"Failed password", l, re.I)]
            accepts = [l for l in lines if re.search(r"Accepted password", l, re.I)]
            keys = [l for l in lines if re.search(r"Accepted publickey", l, re.I)]
            invalids = [l for l in lines if re.search(r"invalid user", l, re.I)]

            result["failed"].extend(fails[-10:])
            result["accepted"].extend(accepts[-10:])
            result["keys"].extend(keys[-10:])
            result["invalid"].extend(invalids[-10:])
        except Exception as e:
            result["summary"] = f"collector failed: {e}"

    total_fails = len(result["failed"])
    total_accepts = len(result["accepted"])
    total_keys = len(result["keys"])
    total_invalid = len(result["invalid"])

    result["summary"] = (
        f"{total_fails} failed, {total_accepts} password logins, "
        f"{total_keys} key logins, {total_invalid} invalid users."
    )
    return result
