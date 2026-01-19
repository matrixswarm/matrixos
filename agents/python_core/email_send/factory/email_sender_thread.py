# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Commander Send the F***in' Email Edition
import ssl
import smtplib
from email.message import EmailMessage
class EmailSenderThread:
    """
    Commander Edition: Hedged Email Worker
    ---------------------------------------------------
    Receives payload: dict with _send_mail args
    Calls agent._send_mail() with exact signature.
    """

    def __init__(self, log, shared):
        self.log = log
        self.shared = shared
        self.payload = shared["context"]["payload"]

    def run(self):
        try:
            msg = EmailMessage()
            msg["From"] = self.payload["from_addr"]
            msg["To"] = self.payload["to_addr"]
            msg["Subject"] = self.payload["subject"]
            msg.set_content(self.payload["body"])

            context = ssl.create_default_context()

            if self.payload["encryption"] == "SSL":
                self.log(f"[EMAIL][CONNECT] Using SSL on {self.payload['smtp_server']}:{self.payload['smtp_port']}")

                #  STEP 1—Test DNS resolution
                try:
                    self.log(f"[EMAIL][DNS] Resolving hostname: {self.payload['smtp_server']}")
                    resolved = ssl.get_server_certificate((self.payload["smtp_server"], self.payload["smtp_port"]))
                    self.log(f"[EMAIL][DNS] Host resolved OK.")
                except Exception as e:
                    self.log("[EMAIL][DNS][ERROR] Hostname resolution failed", error=e)
                    raise

                #  STEP 2—Socket reachability test BEFORE smtplib wraps it
                import socket
                try:
                    self.log(f"[EMAIL][SOCKET] Testing TCP connect to {self.payload['smtp_server']}:{self.payload['smtp_port']}")
                    sock = socket.create_connection((self.payload["smtp_server"], self.payload["smtp_port"]), timeout=10)
                    sock.close()
                    self.log("[EMAIL][SOCKET] TCP connection succeeded.")
                except Exception as e:
                    self.log("[EMAIL][SOCKET][ERROR] TCP connection failed", error=e)
                    raise

                #  STEP 3—Try SSL wrapper handshake alone
                try:
                    self.log("[EMAIL][SSL] Starting SSL handshake test...")
                    with smtplib.SMTP_SSL(self.payload['smtp_server'], self.payload['smtp_port'], context=context, timeout=10) as test:
                        self.log("[EMAIL][SSL] Handshake OK (pre-login).")
                except Exception as e:
                    self.log("[EMAIL][SSL][HANDSHAKE_ERROR] SSL handshake failed", error=e)
                    raise

                #  STEP 4—If handshake works, try login explicitly
                try:
                    self.log(f"[EMAIL][LOGIN] Attempting login as {self.payload['from_addr']}")
                    with smtplib.SMTP_SSL(self.payload["smtp_server"], self.payload["smtp_port"], context=context, timeout=10) as server:
                        server.login(self.payload["from_addr"], self.payload["password"])
                        self.log("[EMAIL][LOGIN] Login OK. Sending message...")
                        server.send_message(msg)
                        self.log("[EMAIL][SEND] Email successfully sent via SSL.")
                except smtplib.SMTPAuthenticationError as auth_err:
                    self.log("[EMAIL][AUTH_ERROR] SMTP authentication failed", error=auth_err)
                    raise
                except Exception as e:
                    self.log("[EMAIL][ERROR] Unknown send failure", error=e)
                    raise

            elif self.payload["encryption"] == "STARTTLS":
                self.log(f"[EMAIL][CONNECT] Using STARTTLS on {self.payload['smtp_server']}:{self.payload['smtp_port']}")
                with smtplib.SMTP(self.payload['smtp_server'], self.payload['smtp_port'], timeout=10) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(self.payload["from_addr"], self.payload["password"])
                    server.send_message(msg)
                    self.log("[EMAIL][SEND] ✅ Sent via STARTTLS.")

            else:
                self.log(f"[EMAIL][CONNECT] Using plain SMTP on {self.payload['smtp_server']}:{self.payload['smtp_port']}")
                with smtplib.SMTP(self.payload["smtp_server"], self.payload["smtp_port"], timeout=10) as server:
                    server.login(self.payload["from_addr"], self.payload["password"])
                    server.send_message(msg)
                    self.log("[EMAIL][SEND] ✅ Sent without encryption.")

        except Exception as e:
            self.log("[EMAIL][ERROR] Send failure", error=e)
        finally:
            # Notify queue manager
            wid = self.shared["context"].get("thread_id")
            mgr = self.shared["context"].get("queue_manager")
            if wid and mgr:
                mgr.thread_finished(wid)