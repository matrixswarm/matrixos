#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Blank Agent Template

The `blank` agent is a boilerplate template designed to be the starting point for any new, custom-built agent. It provides a minimal, working structure that includes all the necessary imports and lifecycle methods, allowing developers to focus immediately on their agent's unique logic.

---
## Key Features

* **Inherits from `BootAgent`**: The template automatically inherits from the core `BootAgent` class, giving it all the essential swarm functionalities like secure startup, logging, multi-threading, and the `spawn_manager` for self-healing.
* **Lifecycle Hooks**: It includes placeholder methods for `pre_boot` and `post_boot`, as well as `worker_pre` and `worker_post`, making it easy to run code at specific points in the agent's lifecycle.
* **Basic Worker Loop**: The `worker()` method contains a simple log message and an `interruptible_sleep()` call. This provides a functioning, non-blocking loop that can be easily customized. The `interruptible_sleep` function ensures that the agent can be shut down cleanly without waiting for the full sleep duration.

---
## How to Use the Template

Follow these steps to create your own custom agent.

### 1. Copy the Template

Copy the `/agent/blank/` directory and rename it for your new agent. For example: `/agent/my_new_agent/`. Rename the enclosed Python file to match: `my_new_agent.py`.

### 2. Customize the Agent Code

Open your new `my_new_agent.py` file and make the following changes:

* **Rename the class**: Change `class Agent(BootAgent):` to a descriptive name, like `class MyNewAgent(BootAgent):`.
* **Implement your logic**: Add your custom code inside the `worker()` method. This is where your agent will perform its primary function.
* **(Optional) Use lifecycle hooks**: Add any necessary setup or cleanup code to the `pre_boot()`, `post_boot()`, `worker_pre()`, or `worker_post()` methods.

### 3. Deploy via Directive

Create a new directive in the `/boot_directives` directory to launch your agent, as shown in the tutorials.

---
## Full Template Code

Here is the fully-commented code for `blank.py` for your reference.

```python
# /agent/blank/blank.py

# Standard library imports
import sys
import os

# Ensure the core swarm libraries are accessible
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

# Core MatrixSwarm imports
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

# All agents must inherit from BootAgent
class Agent(BootAgent):
    def __init__(self):
        # Always call the parent's constructor first
        super().__init__()
        # Set a unique name for your agent for logging purposes
        self.name = "BlankAgent"

    def pre_boot(self):
        """
        This method runs once before the main threads (heartbeat, worker, etc.) are started.
        Ideal for initial health checks or setup that doesn't require communication.
        """
        self.log("[BLANK] Pre-boot checks complete.")

    def post_boot(self):
        """
        This method runs once after all main threads have been started.
        """
        self.log("[BLANK] Post-boot ready. Standing by.")

    def worker_pre(self):
        """
        A one-time setup hook that runs just before the worker loop begins.
        """
        self.log("Boot initialized. Port online, certs verified.")

    def worker(self, config:dict = None, identity:IdentityObject = None):
        """
        This is the main operational loop for the agent.
        Your agent's primary logic goes here. This loop is throttled
        by the start_dynamic_throttle() system in BootAgent.
        """
        self.log("[BLANK] Worker loop alive.")
        print("Guess what time it is?")

        # Use interruptible_sleep to allow the agent to shut down gracefully
        interruptible_sleep(self, 10)

    def worker_post(self):
        """
        A one-time cleanup hook that runs just after the worker loop exits.
        """
        self.log("HTTPS interface shutting down. The swarm will feel it.")

# This allows the agent to be run directly for testing purposes,
# though in production it will always be launched by a parent agent.
if __name__ == "__main__":
    agent = Agent()
    agent.boot()