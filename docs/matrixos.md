                         ┌─────────────────────────┐
                         │       Phoenix GUI       │
                         │  (Swarm Feed, Cockpit)  │
                         └──────────┬──────────────┘
                                    │
                       ┌────────────┴──────────────┐
                       │        MATRIX (Kernel)    │
                       │  - cmd_replace_source     │
                       │  - cmd_delete_agent       │
                       │  - cmd_restart_subtree    │
                       │  - Reaper/Scavenger       │
                       └───────┬────────┬──────────┘
                               │        │
                     ┌─────────┘        └─────────┐
             ┌─────────────┐               ┌──────────────┐
             │  Universe A │               │  Universe B  │
             │ (App/cluster)              │ (App/cluster)│
             └───────┬─────┘               └──────┬──────┘
                     │                           │
          ┌──────────┴───────────┐     ┌─────────┴─────────┐
          │   Agent Tree Nodes   │     │   Agent Tree Nodes │
          │ (C++, Rust, Python)  │     │ (C++, Rust, Python)│
          └───────┬──────────────┘     └─────────┬─────────┘
                  │                              │
   ┌──────────────┴───────────────┐   ┌──────────┴─────────────┐
   │       BootAgent Contract      │   │     BootAgent Contract │
   │  - Vault Boot                 │   │  - Vault Boot          │
   │  - Logs → comm_static         │   │  - Logs → comm_static  │
   │  - Heartbeats → comm_runtime  │   │  - Heartbeats → comm_runtime │
   │  - Incoming packets           │   │  - Incoming packets    │
   │  - Spawn/resurrect children   │   │  - Spawn/resurrect     │
   └──────────────────────────────┘   └────────────────────────┘

                        Parallel Filesystem Layer
   ┌───────────────────────────────────────────────────────────────────┐
   │ /matrix/comm_runtime (tmpfs) → signals, heartbeats, die, incoming │
   │ /matrix/comm_static  (disk) → logs, artifacts, spawn history      │
   └───────────────────────────────────────────────────────────────────┘
