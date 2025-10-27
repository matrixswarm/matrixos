# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import re

def parse_results(lines):
    """
    Generic log parser that classifies lines into errors, warnings, and notices.
    """
    result = {
        "summary": "",
        "errors": [],
        "warnings": [],
        "notices": [],
    }

    for line in lines:
        lower = line.lower()
        if "error" in lower or re.search(r"\[error\]", lower):
            result["errors"].append(line)
        elif "warn" in lower or re.search(r"\[warn(ing)?\]", lower):
            result["warnings"].append(line)
        elif "notice" in lower:
            result["notices"].append(line)

    err_count = len(result["errors"])
    warn_count = len(result["warnings"])
    note_count = len(result["notices"])

    result["summary"] = (
        f"{err_count} errors, {warn_count} warnings, "
        f"{note_count} notices in last {len(lines)} lines."
    )

    # Limit samples to last 10 of each
    result["errors"] = result["errors"][-10:]
    result["warnings"] = result["warnings"][-10:]
    result["notices"] = result["notices"][-10:]

    return result
