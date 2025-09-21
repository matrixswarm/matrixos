#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# MatrixSwarm Architecture

This document provides a high-level overview of the MatrixSwarm architecture, from the initial boot sequence to inter-agent communication. Understanding these core concepts is key to developing for and extending the swarm.

---
## 1. The Boot Process

The entire swarm is brought to life by the `site_boot.py` script. This process is designed to be secure, configurable, and robust.

1.  **Initiation**: A user runs `python3 site_ops/site_boot.py --universe <id> --directive <name>`.
2.  **Directive Loading**: The script loads the specified directive file (e.g., `gatekeeper-demo.py`) from the `/boot_directives` directory. This file contains the Python dictionary that defines the entire agent hierarchy.
3.  **Tree Parsing**: The `TreeParser` class is initialized with the directive. It recursively walks through the agent tree to:
    * Validate the structure and remove any malformed nodes.
    * Detect and reject any agents with duplicate `universal_id` values.
    * Assign a unique cryptographic identity (a **Vault**) to every single node in the tree. This Vault contains the agent's new public/private key pair and an identity token signed by the master "Matrix" agent's private key.
4.  **Spawning the Core**: The `CoreSpawner` class is initialized with the system's Python environment details.
5.  **Matrix Launch**: Finally, `site_boot.py` uses the `CoreSpawner` to launch the root `matrix` agent. This is the only agent launched directly by the boot script. All other agents are subsequently launched by their "parent" agent within the swarm.

---
## 2. Secure Agent Spawning

To avoid exposing sensitive information (like private keys) during agent creation, MatrixSwarm uses a secure spawning mechanism powered by `ghost_vault.py`.

1.  **Payload Assembly**: When an agent (like Matrix) decides to spawn a child, its `CoreSpawner` gathers all necessary configuration data for the new agent—paths, arguments, and its unique cryptographic **Vault**—into a single Python dictionary called a `payload`.
2.  **Encryption**: The spawner calls the `build_encrypted_spawn_env()` function. This function:
    * Generates a secure, single-use AES-256 key.
    * Encrypts the entire `payload` dictionary with this key.
    * Saves the resulting ciphertext to a temporary `.vault` file.
3.  **Secure Handoff**: The spawner launches the new agent as a `subprocess.Popen` command. It passes only two environment variables to the new process:
    * `VAULTFILE`: The path to the temporary encrypted `.vault` file.
    * `SYMKEY`: The single-use AES key needed to decrypt the vault.
4.  **Cleanup**: The `CoreSpawner` does not hold onto the key. The key exists only for the new agent process, ensuring a secure handoff of credentials.

---
## 3. The Agent Lifecycle

Every agent in the swarm, regardless of its function, is built on the `BootAgent` class, which dictates its lifecycle.

1.  **Waking Up**: The first thing a newly spawned agent process does is call `decrypt_vault()`. It reads the `VAULTFILE` and `SYMKEY` from its environment, decrypts its configuration payload, and loads its identity, keys, and paths into memory.
2.  **Starting Threads**: With its configuration loaded, the agent immediately starts several background threads to manage its core functions:
    * **`heartbeat`**: Periodically writes a timestamp to a file in its `/comm` directory to signal to the swarm that it's alive.
    * **`packet_listener`**: Constantly watches its `/comm/incoming` directory for new command files from other agents.
    * **`spawn_manager`**: If the agent has children defined in its directive, this thread monitors them. If a child agent goes silent (stops producing heartbeats), this thread will automatically re-spawn it using the **Secure Agent Spawning** process described above.
    * **`worker`**: This is the main thread where the agent's unique logic is executed. Developers override the `worker()` method to define what an agent actually does.

---
## 4. The Packet Delivery System

Agents do not communicate through traditional network sockets or APIs. Instead, they use a secure, file-based messaging queue.

1.  **Packet Creation**: An agent wanting to send a message creates a `Packet` object. This object contains a `handler` (the function the receiving agent should run) and a `content` payload.
2.  **Secure Delivery**: The sending agent uses a `DeliveryAgent`. This agent:
    * Takes the `Packet` and uses a cryptographic "Football" object to encrypt and sign the contents with the sender's identity.
    * Writes the resulting encrypted JSON to a temporary file.
    * Performs an **atomic** `os.replace` to move the temporary file into the target agent's `/comm/incoming` directory. This atomic operation prevents the receiver from ever reading a partially written file.
3.  **Reception and Processing**: The receiving agent's `packet_listener` thread detects the new file. It uses a `ReceptionAgent` to:
    * Read the encrypted file.
    * Use its own "Football" to decrypt the content and, most importantly, cryptographically verify the sender's signature against the master Matrix public key.
    * If the signature is valid, it passes the packet's `handler` and `content` to the agent's main logic for processing.
 ---
## The Service Manager: Role-Based Service Discovery

To prevent agents from being tightly coupled (e.g., forcing the `apache_watchdog` to know the specific `universal_id` of a `discord_relay`), MatrixSwarm uses a **role-based service discovery** system. Agents don't need to know about each other by name; they only need to know about the *role* or *function* they require.

This system is defined by the `service-manager` block within an agent's `config` in a directive.

### The Service Provider

## The Service Manager: Advanced Role-Based Service Discovery

To prevent agents from being tightly coupled (e.g., forcing the `apache_watchdog` to know the specific `universal_id` of a `discord_relay`), MatrixSwarm uses a **role-based service discovery** system. Agents don't need to know about each other by name; they only need to know about the *role* or *function* they require.

This system is defined by the `service-manager` block within an agent's `config` in a directive.

---
### The Service Provider

An agent that can perform a specific task "advertises" its capabilities by defining them in its `service-manager` block.

For example, the `discord_relay` agent in the `gatekeeper-demo.py` directive advertises that it can handle communication and alerts.

```python
# From gatekeeper-demo.py
"config": {
    "bot_token": os.getenv("DISCORD_TOKEN"),
    "channel_id": os.getenv("DISCORD_CHANNEL_ID"),
    "service-manager": [{
        "role": ["comm", "comm.security", "hive.alert.send_alert_msg", "comm.*"],
        "scope": ["parent", "any"],
        "auth": {"sig": True},
        "priority": 10,
        "exclusive": False
    }]
}
```

role: A list of function names this agent can perform. hive.alert.send_alert_msg is a role that means "able to send an alert."

scope: Defines which other agents this service is available to.

The Service Consumer
An agent that needs a function performed (like sending an alert) does not look for a specific agent. Instead, it asks the swarm for any agent that can fulfill the required role.

The apache_watchdog agent does exactly this in its alert_operator function.
Python

### From apache_watchdog.py
def alert_operator(self, message=None):
    # ... (packet creation code) ...

    # Ask the swarm: "Find all agents that can handle this role."
    alert_nodes = self.get_nodes_by_role("hive.alert.send_alert_msg")
    if not alert_nodes:
        self.log("[WATCHDOG][ALERT] No alert-compatible agents found.")
        return

    # Send the packet to every agent that responded.
    for node in alert_nodes:
        # ... (delivery agent code) ...
        
### The Benefit: A Decoupled and Flexible Swarm
This architecture is incredibly flexible. If you decide you want alerts to go to Telegram instead of Discord, you don't need to modify the apache_watchdog agent's code. You simply update your directive: remove the service-manager block from the Discord agent and add it to the telegram_relay agent.

The watchdog will continue to ask for the "hive.alert.send_alert_msg" role, and the swarm will now direct its request to the Telegram agent. This allows you to hot-swap service providers and reconfigure the swarm's behavior without ever touching the underlying agent code.

---
## Dynamic Agent Configuration (Real-Time Updates)
A standout feature of MatrixSwarm is the ability to change an agent's configuration while it is running. This is handled by the _throttled_worker_wrapper method in BootAgent, which every agent inherits.

How it Works
Config Directory: Every agent has a dedicated /comm/{universal_id}/config/ directory.

Monitoring: The _throttled_worker_wrapper function constantly monitors this directory for new .json files.

Update Trigger: To update an agent, you simply drop a new JSON file into its /config directory. This file contains the new configuration dictionary.

Secure Loading: The wrapper detects the new file, securely decrypts it using the swarm's encryption protocols, and loads its content.

Injection into Worker: This new config dictionary is then passed as the config argument into the very next execution of the agent's worker() method.

Cleanup: After the new configuration is loaded, the .json file is deleted from the /config directory.

This allows for live, dynamic tuning of the entire swarm. For example, you could drop a new config file into a redis_watchdog's folder to change its check_interval_sec from 10 seconds to 60 seconds without ever stopping or restarting the agent.

---


## Universe Segregation: The Swarm Session

A core feature of MatrixSwarm is its ability to run multiple, completely isolated "universes" on the same machine without conflict. This is achieved through a session-based directory structure managed by two key components: `SwarmSessionRoot` and `PathManager`.

### The Session Root (`SwarmSessionRoot`)

When `site_boot.py` initiates a new swarm, it first creates a `SwarmSessionRoot` object. This class acts as a **singleton**, meaning there is only one instance of it for the entire boot process. Its job is to establish the unique, segregated "world" for that specific swarm instance.

1.  **Unique Path Creation**: It generates a unique base path using the `universe_id` and a current timestamp (the `reboot_uuid`). This creates the segregated directory structure: `/matrix/<universe_id>/<YYYYMMDD_HHMMSS>/`.
2.  **Core Directories**: Inside this unique base path, it immediately creates the two fundamental directories for the swarm's operation: `.../comm/` and `.../pod/`.
3.  **The "Latest" Symlink**: To make it easy to find the most recent session for a given universe, `SwarmSessionRoot` creates a symbolic link (`symlink`). This link points from a stable path to the timestamped session directory: `/matrix/<universe_id>/latest` → `/matrix/<universe_id>/<YYYYMMDD_HHMMSS>/`. The `resolve_latest_symlink` function can also be used to repair this link if it's broken.

### The Path Manager (`PathManager`)

While `SwarmSessionRoot` *creates* the session, the `PathManager` *distributes* this information to the rest of the system.

When components like `CoreSpawner` or `BootAgent` need to know where the `comm` or `pod` directories are, they instantiate a `PathManager` with the `use_session_root=True` flag.

The `PathManager` then communicates with the `SwarmSessionRoot` singleton to get the correct, session-specific paths. This ensures that every component, from the spawner to the individual agents, is operating within the same segregated "world" that was created at boot time.

Together, these two files guarantee that every swarm instance is self-contained, preventing agents from different universes or different boot sessions from ever interfering with one another.

## The Cryptographic Football: Secure Packet Handling

At the core of MatrixSwarm's secure communication is a class named `Football`. Think of a "football" as a cryptographic briefcase that an agent carries. It holds all the keys, identity papers, and instructions needed to either send a secure message or receive and verify one.

Every time an agent wants to send or receive a packet, it first prepares a `Football` object with the correct settings for that specific interaction.

### How the Football Works

The `Football` class is essentially a highly sophisticated configuration object for the `PacketEncryptor` and `PacketDecryptor`. It doesn't perform the encryption itself, but it tells the encryptors *how* to do it.

A single `Football` instance can be configured to:
* Use symmetric (AES) or asymmetric (RSA) encryption.
* Sign the payload with a private key to prove authenticity.
* Verify the signature of a received payload.
* Embed the sender's identity within the encrypted packet.
* Manage a collection of trusted identities (both its own and those of its communication partners).

### Key Concepts

#### 1. Identity Management (`add_identity` and `load_identity_file`)
Before an agent can communicate, its `Football` must be loaded with identities.
* **`add_identity(vault, ...)`**: This method loads an agent's own `vault` (containing its private key and signed identity token) into the Football. This is used to prove who the sender is. The method verifies that the private key matches the public key and that the identity token is correctly signed by the master Matrix key.
* **`load_identity_file(universal_id, ...)`**: When sending a packet to another agent, this method is used to load the *recipient's* public key from the filesystem. This public key is then used to securely encrypt the one-time AES key for the message, ensuring only the intended recipient can decrypt it.

#### 2. The Packet Encryption Factory
The `packet_encryption_factory` is a simple but critical function that looks at the `Football` and the desired mode (`encrypt` or `decrypt`) and returns the correct processing object (`PacketEncryptor` or `PacketDecryptor`), fully configured with the settings from the `Football`.

#### 3. The End-to-End Process (Sending a Packet)
1.  An agent creates a `Packet` with a `handler` and `content`.
2.  It gets a new `Football` object.
3.  It calls `add_identity()` to load its own identity into the `Football`.
4.  It calls `load_identity_file()` to load the recipient's public key into the `Football`.
5.  It gets a `DeliveryAgent` and passes it the `Football`.
6.  The `DeliveryAgent` uses the `Football` to encrypt, sign, and write the packet to the recipient's `/incoming` directory.

This entire process, orchestrated by the `Football`, guarantees that every message in the swarm is secure, authenticated, and delivered only to its intended recipient.

## The Secure Packet Protocol (`PacketCryptoMixin`)

While the `Football` class acts as the strategist for secure communication, the `PacketCryptoMixin` is the cryptographic engineer that executes the plan. It defines the precise, multi-layered process for wrapping and unwrapping every packet that gets sent between agents.

### Building a Secure Packet (`build_secure_packet`)

When an agent sends a message, the `PacketEncryptor` uses this mixin to construct the secure packet in the following order:

1.  **Create the Sub-Packet**: The raw payload is wrapped in a "sub-packet" that includes a timestamp.
2.  **Embed Identity**: If configured in the `Football`, the sender's full, signed identity token (the one signed by Matrix) is embedded inside the sub-packet. This proves who sent the message.
3.  **Sign the Sub-Packet**: The entire sub-packet (payload + identity) is then signed using the **sender's private key**. This signature proves that the message has not been tampered with and was sent by the claimed identity.
4.  **Encrypt the Final Packet**: Finally, the sub-packet and its signature are wrapped in an outer packet. This entire outer packet is then encrypted using **AES-256-GCM**.
    * A new, single-use AES key is generated for this one message.
    * This AES key itself is then encrypted using the **recipient's public key** (which was loaded into the Football).
    * The encrypted AES key and the AES-encrypted payload are bundled together into the final file that gets delivered.

### Unpacking a Secure Packet (`unpack_secure_packet`)

When an agent receives a file, the `PacketDecryptor` uses this mixin to reverse the process, ensuring security at every step:

1.  **Decrypt the AES Key**: The receiving agent uses its **own private key** to decrypt the single-use AES key that was bundled with the packet.
2.  **Decrypt the Packet**: It uses the now-decrypted AES key to decrypt the main payload, revealing the outer packet (the sub-packet and the sender's signature).
3.  **Verify the Identity's Signature**: It first checks the signature on the embedded identity token to ensure it was legitimately signed by the master Matrix public key.
4.  **Verify the Packet's Signature**: If the identity is valid, it then uses the **public key from the embedded identity** to verify the signature on the sub-packet. This proves that the message was not altered in transit and was indeed sent by the agent whose identity is attached.
5.  **Return the Payload**: Only if all checks pass is the original, decrypted payload returned to the agent for processing.

This layered approach guarantees **confidentiality** (only the recipient can read it), **integrity** (the message wasn't tampered with), and **authenticity** (the sender is who they claim to be).

---
## 1. The Boot Process & Tree Sanitization

The swarm is brought to life by `site_boot.py`. A key feature of this process is the `TreeParser`'s ability to sanitize the agent directive before launch.

1.  **Directive Loading**: The specified directive file is loaded.
2.  **Node Stripping**: The `TreeParser`'s **`strip_disabled_nodes`** method is immediately called. It recursively scans the directive and removes any agent (and its entire subtree of children) that has `"enabled": false` set in its configuration. This allows for easy testing and debugging without modifying the directive's structure.
3.  **Tree Parsing & Validation**: The now-sanitized tree is parsed. The `TreeParser` validates the structure, rejects duplicates, and assigns a unique cryptographic **Vault** to every enabled node.
4.  **Matrix Launch**: The `CoreSpawner` launches the root `matrix` agent, which then spawns its children based on the clean and validated tree.

---
## 2. The Forensic Detective System

To provide intelligent, automated root cause analysis, the swarm now employs a sophisticated forensic ecosystem.

1.  **Watchdog Agents**: Specialized agents (`SystemHealthMonitor`, `ApacheWatchdog`, `GhostWire`, etc.) constantly monitor specific aspects of the system. They send **`INFO`**, **`WARNING`**, or **`CRITICAL`** status reports to the `ForensicDetective`.
2.  **The Forensic Detective**: This central agent acts as an incident response brain.
    * **Event Ingestion**: It listens for status reports from all watchdog agents.
    * **De-duplication**: It hashes incoming events to de-duplicate noise, tracking the `count` and `last_seen` time of identical warnings.
    * **Incident Trigger**: When it receives a **`CRITICAL`** packet (e.g., `nginx` is `DOWN`), it initiates a new forensic incident.
    * **Correlation**: It gathers all other `WARNING` or `ERROR` events that occurred within a 120-second window *before* the critical failure.
    * **Automated Analysis**: It consults a `CAUSE_PRIORITIES` list to determine the most probable root cause from the correlated events (e.g., "Low disk space" takes precedence over "High CPU").
    * **Specialized Investigators**: It dynamically loads a service-specific "investigator" (e.g., for `nginx`) which adds contextual details, like the last few lines of an error log, to the report.
    * **Unified Alerting**: It constructs a single, rich alert packet containing both a simple text message and detailed embed data, then sends it to all agents with the `hive.alert.send_alert_msg` role.
    * **Data Archiving**: It saves a complete JSON summary of the incident, including the trigger, all correlated events, and the final report, to its `/summary` directory for later analysis.

---
## 3. The Agent Lifecycle & Communication

Every agent inherits from `BootAgent`, which provides a standardized lifecycle and communication framework.

* **Secure Initialization**: Agents wake up by decrypting their unique Vault file.
* **Core Threads**: Standard threads for `heartbeat`, `packet_listener`, and `spawn_manager` are launched automatically.
* **Packet-Based Communication**: The `pass_packet` and `catch_packet` methods in `BootAgent` provide a high-level, simplified interface for secure, file-based messaging.
    * **`pass_packet`**: Encapsulates the entire process of creating a cryptographic "Football", loading the target's identity, and delivering an encrypted, signed packet.
    * **`catch_packet`**: Handles receiving a packet, decrypting it, and cryptographically verifying the sender's identity before returning the payload.

---
*The rest of the architecture document (`SERVICE MANAGER`, `DYNAMIC CONFIGURATION`, etc.) remains accurate and does not require changes at this time.*     