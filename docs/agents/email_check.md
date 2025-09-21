#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Email Check

The `email_check` agent connects to an email account via IMAP and processes unseen emails.

---
## How it Works

In its `worker_pre()` method, the agent establishes a persistent connection to the configured IMAP server. In its main `worker()` loop, it searches for any emails marked as `UNSEEN`. For each new email found, it fetches the content and logs the subject line. This agent can be extended to parse email bodies and forward commands to other agents.

---
## Configuration

Credentials can be provided via the directive's `config` block or through environment variables (e.g., in a `.env` file).

* **`imap_host`**: The hostname of the IMAP server.
* **`email`**: The email address to check.
* **`password`**: The password for the email account.
* **`report_to`** (Default: `"mailman-1"`): The `universal_id` of another agent to send parsed email data to (functionality can be extended).

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "email-inbox-1",
            "name": "email_check",
            "config": {
                "imap_host": "imap.gmail.com",
                "email": "your_email@gmail.com",
                "password": "your_app_password"
            }
        }
    ]
}