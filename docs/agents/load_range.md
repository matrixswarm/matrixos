#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Load Range

The `load_range` agent is a system performance monitor. It periodically samples the system's 1-minute load average and aggregates the data to generate daily summary reports, helping you understand your server's performance patterns.

---
## How it Works

In its `worker()` loop, the agent uses the `psutil` library to get the system load average and the CPU usage of active processes. It stores these samples in memory. Once per day, it analyzes the collected samples to generate a report containing:
* **Load Distribution**: The percentage of time the system spent in different load ranges (e.g., `<10%`, `10-50%`, etc.).
* **Hourly Contribution**: The hours of the day that contributed most to the total system load.
* **Top Processes**: The top 3 most CPU-intensive processes over the 24-hour period.

This report is then written to a daily summary file in its `/comm/{universal_id}/summary` directory.

---
## Configuration

The `load_range` agent requires no special configuration in the directive. Its sample interval and reporting window are hardcoded.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "load-monitor-1",
            "name": "load_range"
        }
    ]
}