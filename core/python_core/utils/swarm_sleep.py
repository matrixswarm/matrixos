# ╔═════════════════════════════════════════════════════════════╗
# ║   THE SWARM IS ALIVE — AGENTS COMING OUT OF EVERY ORIFICE   ║
# ║       Please take as many as your system can support        ║
# ╚═════════════════════════════════════════════════════════════╝
# Disclaimer: If your system catches fire, enters recursive meltdown,
# or you OD on die cookies — just remember: we met at a Star Trek convention.
# You were dressed as Data. I was the Captain. That’s all we know about each other.
# He said something about agents… then started telling people to fork off.
# I don’t know, something was up with that guy.

# 🧠 Swarm Utility: interruptible_sleep()
import time

def interruptible_sleep(agent, seconds):
    end = time.time() + seconds
    while time.time() < end:
        if not agent.running:
            agent.log("[SLEEP] Interrupted sleep due to shutdown flag.")
            return
        time.sleep(0.2)  # shorter tick, more responsive