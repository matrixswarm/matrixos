import subprocess

class Investigator:
    """
    A default forensic investigator that performs generic system checks.
    """

    def __init__(self, agent_ref, service_name, recent_events):
        self.agent = agent_ref
        self.service_name = service_name
        self.recent_events = recent_events

    def investigate(self):
        self.agent.log(f"Running DEFAULT forensic checks for {self.service_name}")
        findings = []

        # Check dmesg for kernel-level errors (like Out of Memory)
        try:
            dmesg_output = subprocess.check_output(["dmesg"], text=True, stderr=subprocess.STDOUT).strip().split('\n')
            last_20_dmesg = "\n".join(dmesg_output[-20:])
            if "Out of memory" in last_20_dmesg or "oom-killer" in last_20_dmesg:
                findings.append("Kernel OOM (Out of Memory) Killer likely terminated a process.")
        except Exception as e:
            self.agent.log(f"dmesg check failed: {e}", level="WARNING")

        if not findings:
            return "No specific cause found in generic system logs."

        return "\n".join(findings)

