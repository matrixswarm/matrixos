# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import re
from collections import Counter

def parse_results(lines):
    """
    Universal log parser for collectors.
    Classifies lines into errors, warnings, and notices, and returns structured stats.
    """
    if not isinstance(lines, list):
        return {"lines": [], "summary": "no lines", "stats": {}}

    result = {
        "lines": lines,
        "summary": "",
        "stats": {},
    }

    counters = Counter()

    for line in lines:
        lower = line.lower()
        if "error" in lower or re.search(r"\[error\]", lower):
            counters["errors"] += 1
        elif "warn" in lower or re.search(r"\[warn(ing)?\]", lower):
            counters["warnings"] += 1
        elif "notice" in lower or re.search(r"\[notice\]", lower):
            counters["notices"] += 1
        elif "fail" in lower:
            counters["failed"] += 1
        elif "invalid" in lower:
            counters["invalid"] += 1

    total = len(lines)
    summary_parts = [f"{v} {k}" for k, v in counters.items()]
    summary = ", ".join(summary_parts) if summary_parts else "no issues found"
    summary += f" in last {total} lines."

    result["summary"] = summary
    counters["total"] = total
    result["stats"] = dict(counters)

    return result
