# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys
import os

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from agents.python_core.email_send.factory.email_queue_manager import EmailQueueManager
from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.class_lib.processes.thread_launcher import ThreadLauncher

class Agent(BootAgent):
    """
    An agent that relays swarm alerts to a specified email address.

    This agent acts as a standard alert handler, listening for commands sent
    to the `cmd_send_alert_msg` handler. It is designed to work reliably
    with modern email providers like Gmail and Outlook by using a secure
    SSL/TLS connection from the outset.
    """
    def __init__(self):
        """
        Initializes the agent and loads its SMTP configuration.

        This method loads all necessary SMTP credentials and server details
        from the agent's directive configuration block.

        Attributes:
            smtp_server (str): The SMTP server hostname (e.g., "smtp.gmail.com").
            smtp_port (int): The SMTP server port (e.g., 465 for SSL).
            from_address (str): The email address to send from.
            password (str): The password or App Password for the sender's email.
            to_address (str): The email address to send the alert to.
        """
        super().__init__()

        try:
            cfg = self.tree_node.get("config", {})
            smtp = cfg.get("smtp", {}) or cfg.get("mail", {})

            self.smtp_server = smtp.get("smtp_server")  # matches your directive
            self.smtp_port = smtp.get("smtp_port")
            self.from_address = smtp.get("smtp_username")  # sender's email
            self.password = smtp.get("smtp_password")
            self.to_address = smtp.get("smtp_to")  # default recipient
            self.encryption = (smtp.get("smtp_encryption") or "SSL").upper().strip()
            self.thread_launcher = ThreadLauncher(self)
            self.queue = EmailQueueManager(log=self.log, thread_launcher=self.thread_launcher)

        except Exception as e:
            self.log(error=e, level="ERROR")

    def cmd_send_email(self, content: dict, packet: dict, identity: IdentityObject = None):
        """Entry point when swarm sends a 'send email' command."""
        try:
            smtp_server = content.get("smtp_server") or self.smtp_server
            raw_port = content.get("smtp_port") or self.smtp_port or 465
            try:
                smtp_port = int(raw_port)
            except (ValueError, TypeError):
                smtp_port = 465

            from_addr = content.get("from") or self.from_address
            to_addr = content.get("to") or self.to_address
            subject = content.get("subject").strip()
            password = content.get("password") or self.password
            encryption = (content.get("smtp_encryption") or self.encryption).upper().strip()
            body = content.get("body", "")

            if not all([smtp_server, from_addr, password, to_addr]):
                self.log("[EMAIL] ❌ Missing required fields.", level="ERROR")
                return

            self.queue.enqueue({
                "smtp_server": smtp_server,
                "smtp_port": smtp_port,
                "encryption": encryption,
                "from_addr": from_addr,
                "to_addr": to_addr,
                "password": password,
                "subject": subject,
                "body": body
            })

        except Exception as e:
            self.log("[EMAIL] ❌ Failed to dispatch email", error=e)

    def cmd_send_alert_msg(self, content: dict, packet, identity: IdentityObject = None):
        """
        The main command handler for receiving and processing swarm alerts.

        This method is triggered when another agent sends a packet to it. It
        extracts the relevant information from the alert, formats it for an
        email, and calls the internal `_send_email` method to dispatch it.

        Args:
            content (dict): The alert payload from the sending agent.
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        if not all([self.smtp_server, self.smtp_port, self.from_address, self.password, self.to_address]):
            self.log("SMTP configuration is incomplete. Cannot send email.", level="ERROR")
            return

        try:
            # The 'cause' of the alert makes a great email subject
            subject = content.get("cause", "MatrixSwarm Alert")

            # Prioritize the pre-formatted message, but fall back to the raw message
            body = content.get("formatted_msg") or content.get("msg") or "No message content provided."

            self.queue.enqueue({
                "agent": self,
                "smtp_server": self.smtp_server,
                "smtp_port": self.smtp_port,
                "encryption": self.encryption,
                "from_addr": self.from_address,
                "to_addr": self.to_address,
                "password": self.password,
                "subject": subject,
                "body": body,
            })

        except Exception as e:
            self.log("Failed to process alert for email sending.", error=e, block="main_try")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
