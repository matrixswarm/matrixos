#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Oracle

The `oracle` agent acts as a gateway to a large language model (LLM), currently OpenAI's GPT-3.5 Turbo. Other agents can send it a prompt, and the `oracle` will query the LLM API and deliver the response back to a target agent. This allows the swarm to leverage advanced AI for reasoning, content generation, and analysis.

---
## How it Works

The agent's primary function is its `msg_prompt` handler. When another agent sends a packet with this handler, the `oracle` takes the following steps:

1.  **Receives Prompt**: It parses the incoming packet for the `prompt` text and an optional `history` of prior messages.
2.  **Queries LLM**: It constructs a request and sends it to the configured OpenAI API endpoint.
3.  **Constructs Reply**: Once the LLM returns a response, the `oracle` agent wraps this response in a new packet.
4.  **Delivers Response**: It drops the response packet as a `.msg` file into the `/incoming` directory of the specified target agent.

---
## Configuration

The agent requires an API key to function.

* **`api_key`**: Your OpenAI API key. This can be set in the directive's `config` block or, preferably, through an environment variable named `OPENAI_API_KEY_2`.

### How to Use

To query the oracle, an agent must send a packet to its `universal_id` with the handler `msg_prompt`.

**Example Request Packet from another agent:**

```python
# In another agent's code...

# The agent to send the final response to
target_agent_id = "my-research-agent-1"

# The prompt for the oracle
prompt_content = {
    "prompt": "Explain the concept of an atomic file operation in three sentences.",
    "target_universal_id": target_agent_id
}

# The main packet to the oracle
request_packet_data = {
    "handler": "msg_prompt",
    "content": prompt_content
}
```
#### ... (standard packet delivery code to send this to the oracle agent)

### Example Directive
This directive launches an oracle agent and another "requester" agent that could query it.
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "oracle-1",
            "name": "oracle",
            "config": {
                # Best practice is to set the key via environment variable
                "api_key": os.getenv("OPENAI_API_KEY_2")
            }
        },
        {
            "universal_id": "requester-1",
            "name": "blank" # Using the blank agent as an example
        }
    ]
}
```
