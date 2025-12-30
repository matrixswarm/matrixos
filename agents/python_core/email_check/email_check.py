# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import json, imaplib, threading, time, uuid, hashlib, socket, ssl
from typing import Dict, Any, Optional, Iterable
from pathlib import Path

from core.python_core.class_lib.crypto.symmetric_encryption.aes.aes import AESHandlerBytesShim
from core.python_core.class_lib.email.email_parser import EmailParser

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep

class Agent(BootAgent):
    """
    Agent for polling IMAP mailboxes on a scheduled basis.

    This agent connects to configured email accounts via IMAP, fetches new messages,
    and stores them in an encrypted format within the agent's static communication
    path (`/matrix/universes/static/<universe>/latest/comm/<email_check_universal_id>/mailbox/<account_id>/`).

    Messages are encrypted using an AES key provided via the Phoenix symmetric
    encryption configuration. The agent also manages local metadata (e.g., mail maps)
    for each account, also encrypted, to track fetched messages and manage
    local/remote deletion staging.

    Core features include:
    - **Configuration Loading:** Extracts account details (server, port, credentials)
      from the agent's configuration tree and monitors a separate encrypted
      `accounts.json.aes` file for dynamic updates.
    - **Scheduled Polling:** Runs a background thread to poll all configured
      accounts at a set interval.
    - **Message Handling:** Fetches new messages (RFC822 bytes), stages, encrypts,
      and stores them, updating metadata to prevent re-download.
    - **Cleanup/Deletion:** Processes staged deletion markers (in `del/`), optionally
      deleting messages remotely via IMAP and removing local files/metadata. It also
      removes orphaned local files not present in the metadata.
    - **Command Surface:** Provides RPC commands for manual actions like:
      - `cmd_list_folders`: Get list of folders on the IMAP server.
      - `cmd_list_mailbox`: Paginate and list metadata for stored emails in a folder.
      - `cmd_retrieve_email`: Decrypt, parse, and return the content of a stored email.
      - `cmd_delete_email`: Stage an email for local and/or remote deletion.
      - `cmd_check_email` / `cmd_fetch_new_mail`: Trigger an immediate poll.
      - `cmd_update_accounts`: Update the `accounts.json.aes` file dynamically.
    - **Alerting:** Broadcasts a swarm alert upon discovering new emails.
    """
    def __init__(self):
        super().__init__()

        try:
            self.AGENT_VERSION = "2.0.0"
            
            cfg = self.tree_node.get("config", {}) or {}

            # --- Extract incoming email config directly from deployment ---
            email_cfg = cfg.get("email", {})

            # live account set keyed by serial -> config dict

            account_serial= email_cfg.get("serial")
            self.accounts = {account_serial: {
                "incoming_server": email_cfg.get("incoming_server"),
                "incoming_port": email_cfg.get("incoming_port", 993),
                "incoming_username": email_cfg.get("incoming_username"),
                "incoming_password": email_cfg.get("incoming_password"),
                "acct_serial": account_serial,
                "incoming_encryption": email_cfg.get("incoming_encryption", "SSL"),
            }}

            self.accounts = self._normalize_accounts(self.accounts)

            #poll interval
            self._interval = int(cfg.get("interval_sec", 30))
            self._poll_interval = int(cfg.get("poll_interval", 300))

            #hard timeout
            socket.setdefaulttimeout(15)

            self._force_poll_now=False

            self.active_mail_sessions = {}
            self._signing_keys = cfg.get('security').get('signing')

            self._aes_key =  cfg.get('security').get('symmetric_encryption').get('key')

            self._aes = AESHandlerBytesShim(self._aes_key)

            #create the mailbox on static comm
            self.mail_root = os.path.join(self.path_resolution["static_comm_path_resolved"], "mailbox")
            os.makedirs(self.mail_root, exist_ok=True)

            #account file location
            self._accounts_file = os.path.join(self.mail_root, "accounts.json.aes")

            self._last_cfg = {}
            self._cfg_lock = threading.Lock()
            self._accounts_lock = threading.Lock()
            self._poll_thread = None

            self._emit_beacon = self.check_for_thread_poke("worker", timeout=self._interval * 2, emit_to_file_interval=10)
            self.beacon_imap_poll = self.check_for_thread_poke("imap_poll_inner", timeout=self._poll_interval * 2, emit_to_file_interval=10)

            self._swarm_feed_alert_role = cfg.get("swarm_feed_alert_role", "swarm_feed.alert")

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    # ---------- path helpers ----------
    def _acct_paths(self, serial: str) -> Dict[str, str]:
        acct = os.path.join(self.mail_root, serial)
        paths = {
            "acct": acct,
            "cur": os.path.join(acct, "cur"),
            "tmp": os.path.join(acct, "tmp"),
            "meta_dir": os.path.join(acct, "meta"),
            "meta_file": os.path.join(acct, "meta", "map.json.aes"),
        }
        for p in (paths["cur"], paths["tmp"], paths["meta_dir"]):
            os.makedirs(p, exist_ok=True)
        return paths

    # ---------- accounts file monitoring ----------
    def _load_accounts_file(self):
        """Load or initialize accounts.json.aes from static comm."""
        try:

            if not os.path.exists(self._accounts_file):
                self._save_accounts_file({})  # create empty
                self.log("[EMAIL_CHECK] Created new accounts.json.aes (no accounts).")
                return {}

            raw = Path(self._accounts_file).read_bytes()
            try:
                data = json.loads(self._aes.decrypt(raw).decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("accounts.json.aes corrupted structure.")
                self.log(f"[EMAIL_CHECK] Loaded {len(data.get('accounts', {}))} account(s) from accounts.json.aes.")
                return data
            except Exception as e:
                # decryption failed
                bad_path = self._accounts_file + f".backup_{int(time.time())}"
                Path(self._accounts_file).rename(bad_path)
                self.log(f"[EMAIL_CHECK] ⚠️ Failed to decrypt accounts.json.aes — backed up as {bad_path}")
                self._save_accounts_file({})
                return {}
        except Exception as e:
            self.log("[EMAIL_CHECK][LOAD-ACCOUNTS][ERROR]", error=e)
            return {}

    def _save_accounts_file(self, data: dict):
        """Encrypt and save connection data structure."""
        try:
            raw = json.dumps(data, indent=2).encode("utf-8")
            ct = self._aes.encrypt(raw)
            tmp = self._accounts_file + ".tmp"
            with open(tmp, "wb") as f:
                f.write(ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._accounts_file)
        except Exception as e:
            self.log("[EMAIL_CHECK][SAVE-CONNECTIONS][ERROR]", error=e)

    def _watch_accounts_file(self):
        """Monitor accounts.json.aes for modifications and reload dynamically."""
        last_mtime = os.path.getmtime(self._accounts_file) if os.path.exists(self._accounts_file) else 0
        while self.running:
            try:
                if os.path.exists(self._accounts_file):
                    current_mtime = os.path.getmtime(self._accounts_file)
                    if current_mtime != last_mtime:
                        data = self._load_accounts_file()
                        accounts = data.get("accounts", {})
                        if accounts:
                            with self._accounts_lock:
                                accounts = self._normalize_accounts(accounts)
                                self.log(f"[EMAIL_CHECK] 🔄 Reloaded {len(accounts)} account(s) from accounts.json.aes.")
                        else:
                            with self._accounts_lock:
                                self.accounts = {}
                                self.log("[EMAIL_CHECK] ⚠️ No accounts in accounts.json.aes — halting polling.")
                        last_mtime = current_mtime
                interruptible_sleep(self, 5)
            except Exception as e:
                self.log("[EMAIL_CHECK][WATCH-CONNECTIONS][ERROR]", error=e)
                interruptible_sleep(self, 10)

    # ---------- metadata I/O (encrypted) ----------
    def _load_meta(self, serial: str) -> Dict[str, Any]:
        """
        Safely load and decrypt mailbox metadata for an account.
        If decryption fails (e.g., due to AES key rotation), backup and rebuild.
        """
        mf = self._acct_paths(serial)["meta_file"]
        if not os.path.exists(mf):
            return {"v": 1, "acct_serial": serial, "last_sync": 0, "imap": {}}

        try:
            ct = Path(mf).read_bytes()
            pt = self._aes.decrypt(ct)
            return json.loads(pt.decode("utf-8"))

        except Exception as e:
            # Most likely AES key mismatch or file corruption
            self.log(f"{e} (serial={serial})", level="ERROR")

            # Backup the broken file for inspection
            try:
                bad_path = mf + f".backup_{int(time.time())}"
                Path(mf).rename(bad_path)
                self.log(f"[EMAIL_CHECK] 🔒 Backup created: {bad_path}")
            except Exception as be:
                self.log(f"{be}", level="ERROR")

            # Emit a clear status hint to the UI
            return {
                "v": 1,
                "acct_serial": serial,
                "last_sync": 0,
                "imap": {},
                "error_code": "AES_DECRYPT_FAIL",
                "error_msg": "Metadata reset due to AES key mismatch or corruption",
            }

    def _save_meta(self, serial: str, meta: Dict[str, Any]) -> None:
        try:
            paths = self._acct_paths(serial)
            raw = json.dumps(meta, separators=(",", ":")).encode("utf-8")
            ct = self._aes.encrypt(raw)
            tmp = paths["meta_file"] + ".tmp"
            with open(tmp, "wb") as f:
                f.write(ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, paths["meta_file"])
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    # ---------- message store (encrypted blobs) ----------
    def _stage_encrypt_store(self, serial: str, uuid_str: str, raw_bytes: bytes) -> str:

        try:
            paths = self._acct_paths(serial)
            tmpf = os.path.join(paths["tmp"], f"{uuid_str}.eml")
            curf = os.path.join(paths["cur"], f"{uuid_str}.eml.aes")
            with open(tmpf, "wb") as f:
                f.write(raw_bytes)
                f.flush()
                os.fsync(f.fileno())
            ct = self._aes.encrypt(raw_bytes)
            with open(curf, "wb") as f:
                f.write(ct)
                f.flush()
                os.fsync(f.fileno())
            os.remove(tmpf)
            return curf

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def _read_uuid(self, serial: str, uuid_str: str) -> bytes:
        curf = os.path.join(self._acct_paths(serial)["cur"], f"{uuid_str}.eml.aes")
        ct = Path(curf).read_bytes()
        return self._aes.decrypt(ct)

    # ---------- IMAP helpers ----------
    def _normalize_imap_username(self, raw_user: str, cfg: Dict[str, Any]) -> str:
        u = (raw_user or "").strip()
        if not u:
            return ""

        if "@" in u:
            # canonicalize just a bit: trim spaces; keep case if you want
            local, domain = u.split("@", 1)
            return f"{local.strip()}@{domain.strip().lower()}"  # lower domain is safe

        # Prefer explicit domain in config (cleanest)
        domain = (cfg.get("incoming_domain") or "").strip().lower()
        if not domain:
            # Fallback: infer from server hostname (only safe for your “mail.dragoart.com” style)
            host = (cfg.get("incoming_server") or "").strip().lower()
            if host.startswith("mail."):
                host = host[5:]
            parts = host.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

        return f"{u}@{domain}"

    def _normalize_accounts(self, accounts: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        for serial, cfg in (accounts or {}).items():
            cfg["incoming_username"] = self._normalize_imap_username(cfg.get("incoming_username", ""), cfg)
        return accounts


    def _imap_connect(self, cfg: Dict[str, Any]) -> imaplib.IMAP4:
        host = cfg.get("incoming_server")
        port = int(cfg.get("incoming_port") or 143)
        enc = (cfg.get("incoming_encryption") or "").upper()
        user = cfg.get("incoming_username")
        pwd = cfg.get("incoming_password")

        try:

            if enc in ("SSL", "TLS", "IMAPS", "SSL/TLS"):
                client = imaplib.IMAP4_SSL(host, port, )
            else:
                client = imaplib.IMAP4(host, port)
            if enc == "STARTTLS":
                client.starttls()
            client.login(user, pwd)
            return client

        except imaplib.IMAP4.error as e:
            err = str(e).lower()
            if "authentication failed" in err or "invalid credentials" in err:
                code = "AUTH_FAILED"
            elif "no response" in err or "not connected" in err:
                code = "CONN_FAILED"
            else:
                code = "IMAP_ERROR"
            self.log(f"[EMAIL_CHECK][ERROR] Login failed ({code}) for user='{user}' host='{host}': {e}")
            raise RuntimeError(code)

        except (socket.gaierror, socket.timeout) as e:
            self.log(f"[EMAIL_CHECK][ERROR] Network error connecting to {host}:{port} — {e}")
            raise RuntimeError("NETWORK_ERROR")

        except ssl.SSLError as e:
            self.log(f"[EMAIL_CHECK][ERROR] SSL handshake error with {host}:{port} — {e}")
            raise RuntimeError("SSL_ERROR")

        except Exception as e:
            self.log(f"[EMAIL_CHECK][ERROR] Unexpected IMAP connect error {host}:{port} — {e}")
            raise RuntimeError("IMAP_UNKNOWN")

    def _list_folders(self, imap: imaplib.IMAP4) -> Iterable[str]:
        typ, data = imap.list()
        if typ != "OK": return ["INBOX"]
        out = []
        for line in data or []:
            if not line: continue
            s = line.decode(errors="ignore")
            # format: b'(\\HasNoChildren) "/" "INBOX"'
            try:
                name = s.split(' "/" ', 1)[1].strip()
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1]
                out.append(name)
            except Exception:
                pass
        return out or ["INBOX"]

    def _extract_rfc822_bytes(self, fetch_resp) -> bytes:
        # fetch_resp like [(b'1234 (UID 1234 RFC822 {N}', b'...raw...'), b')']
        for part in fetch_resp:
            if isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray)):
                return bytes(part[1])
        return b""

    def _extract_flags(self, fetch_resp) -> Iterable[str]:
        # light parser: not critical; optional
        return []

    def _extract_internaldate(self, fetch_resp) -> int:
        return 0

    # ---------- polling ----------
    def _poll_account_once(self, serial: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Poll one IMAP account:
          • Process staged deletions (from /del)
          • Remove orphaned local files not in meta
          • Sync with IMAP and optionally delete remote messages after fetch
        """

        try:

            meta = self._load_meta(serial)
            imap = None
            new_count = 0
            deleted_count = 0
            nuked_orphans = 0

            imap = self._imap_connect(cfg)
            folders = cfg.get("folders") or ["INBOX"]
            if folders == ["*"]:
                folders = list(self._list_folders(imap))

            acct_path = self._acct_paths(serial)
            cur_dir = acct_path["cur"]
            del_dir = os.path.join(acct_path["acct"], "del")
            os.makedirs(del_dir, exist_ok=True)


            # === Phase 1: Cleanup stale markers ===
            for fname in list(os.listdir(del_dir)):
                if not fname.endswith(".json"):
                    continue
                try:
                    marker_path = os.path.join(del_dir, fname)
                    with open(marker_path, "r") as f:
                        marker = json.load(f)

                    uuid_str = fname.split(".json")[0]
                    folder = marker.get("folder", "INBOX")
                    remote_flag = bool(marker.get("remote", False))
                    deleted_remote = False

                    # Attempt IMAP delete if requested
                    if remote_flag:
                        try:
                            imap.select(folder)
                            for uid, rec in (meta.get("imap", {}).get(folder, {}) or {}).items():
                                if rec.get("uuid") == uuid_str:
                                    imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
                                    imap.expunge()
                                    deleted_remote = True
                                    break
                        except Exception as e:
                            self.log(f"[EMAIL_CHECK][DEL][WARN] IMAP delete failed for {uuid_str}: {e}")

                    # Verification
                    verified = False
                    if remote_flag:
                        try:
                            imap.select(folder)
                            typ, data = imap.uid("SEARCH", None, "ALL")
                            active_uids = set((data[0] or b"").decode().split())
                            verified = not any(
                                uid in active_uids for uid, rec in (meta.get("imap", {}).get(folder, {}) or {}).items()
                                if rec.get("uuid") == uuid_str)
                        except Exception:
                            pass
                    else:
                        verified = True

                    if verified:
                        # purge from meta
                        for uid, rec in list((meta.get("imap", {}).get(folder, {}) or {}).items()):
                            if rec.get("uuid") == uuid_str:
                                del meta["imap"][folder][uid]
                                break


                        # delete file
                        curf = os.path.join(cur_dir, f"{uuid_str}.eml.aes")
                        if os.path.exists(curf):
                            try:
                                os.remove(curf)
                                self.log(f"[EMAIL_CHECK] 💀 Deleted local file {uuid_str}.eml.aes")
                            except Exception as e:
                                self.log(f"[EMAIL_CHECK][WARN] Failed to remove {curf}: {e}")

                        # purge from meta and resave
                        for uid, rec in list((meta.get("imap", {}).get(folder, {}) or {}).items()):
                            if rec.get("uuid") == uuid_str:
                                del meta["imap"][folder][uid]
                                break

                        self._save_meta(serial, meta)

                        # remove marker
                        os.remove(marker_path)
                        deleted_count += 1
                        self.log(
                            f"[EMAIL_CHECK] ✅ Confirmed delete of {uuid_str} (remote={remote_flag}) and updated meta.")

                    else:
                        self.log(f"[EMAIL_CHECK][PENDING] {uuid_str} not yet confirmed deleted.")
                except Exception as e:
                    self.log(f"[EMAIL_CHECK][DELETE-FAIL] {fname}: {e}")

            # === Phase 2: Nuke orphaned files not in metadata ===
            valid_uuids = {rec["uuid"] for folder_map in meta.get("imap", {}).values() for rec in folder_map.values()}
            for fname in list(os.listdir(cur_dir)):
                if not fname.endswith(".eml.aes"):
                    continue
                uuid_str = fname.replace(".eml.aes", "")
                if uuid_str not in valid_uuids:
                    try:
                        os.remove(os.path.join(cur_dir, fname))
                        nuked_orphans += 1
                        self.log(f"[EMAIL_CHECK] 💀 Orphaned file removed: {uuid_str}.eml.aes")
                    except Exception as e:
                        self.log(f"[EMAIL_CHECK][NUKE-FAIL] {fname}: {e}")

            # === Phase 3: Standard mailbox poll ===
            for folder in folders:
                last_map = meta["imap"].setdefault(folder, {})
                imap.select(folder, readonly=False)
                typ, data = imap.uid("SEARCH", None, "ALL")
                if typ != "OK":
                    continue
                uid_list = (data[0] or b"").decode().split()

                for uid in uid_list:
                    if uid in last_map:
                        continue
                    typ, msg = imap.uid("FETCH", uid, "(RFC822 FLAGS INTERNALDATE RFC822.SIZE)")
                    if typ != "OK" or not msg:
                        continue

                    raw = self._extract_rfc822_bytes(msg)
                    u = str(uuid.uuid4())
                    curf = self._stage_encrypt_store(serial, u, raw)
                    rec = {
                        "uuid": u,
                        "flags": self._extract_flags(msg),
                        "internaldate": self._extract_internaldate(msg),
                        "size": len(raw),
                        "hash": hashlib.sha256(raw).hexdigest(),
                        "last_fetch": int(time.time()),
                    }
                    last_map[uid] = rec
                    new_count += 1

                    # Only nuke IMAP after successful store and config allows it
                    if cfg.get("delete_after_download", True):
                        try:
                            imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
                            self.log(f"[EMAIL_CHECK] 🗑 Marked IMAP UID {uid} deleted (post-download).")
                        except Exception as e:
                            self.log(f"[EMAIL_CHECK][NUKE-IMAP] Failed to delete UID {uid}: {e}")

                    if new_count % 25 == 0:
                        self._save_meta(serial, meta)

                # expunge after full folder cycle
                try:
                    imap.expunge()
                except Exception:
                    pass


            meta["last_sync"] = int(time.time())
            self._save_meta(serial, meta)

            #If there are new messages send notification back to the swarm feed
            if new_count > 0:
                self._broadcast_swarm_alert(
                    f"📬 {new_count} new email(s) arrived for {serial}",
                    level="info"
                )
            return {
                "status": "ok",
                "serial": serial,
                "new": new_count,
                "deleted": deleted_count,
                "nuked_orphans": nuked_orphans,
            }

        except Exception as e:
            self.log(f"[EMAIL_CHECK][ERROR] Poll failed for {serial}: {e}")
            return {"status": "error", "serial": serial, "error": str(e)}

        finally:
            try:
                if imap:
                    imap.logout()
            except Exception:
                pass

    def _poll_all_accounts_once(self, serial: Optional[str] = None) -> Dict[str, Any]:

        try:
            if serial:
                #this is a request to list messages from an box
                cfg = self.accounts.get(serial)
                if not cfg:
                    return {"status": "error", "error": "unknown_serial", "detail": serial}
                return self._poll_account_once(serial, cfg)
            results = {}
            for s, cfg in self.accounts.items():
                results[s] = self._poll_account_once(s, cfg)
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    # ---------- command surface ----------
    def cmd_list_folders(self, content, packet, identity=None):
        serial = content.get("serial")
        imap = self._imap_connect(self.accounts[serial])
        return {"status": "ok", "folders": list(self._list_folders(imap))}

    def cmd_list_mailbox(self, content, packet, identity=None):

        serial = content.get("serial") #not serial of agent, serial of account you want to lookup
        folder = content.get("folder", "INBOX")

        limit = int(content.get("limit", 20))
        offset = int(content.get("offset", 0))

        try:
            session_id = content.get("session_id")
            meta = self._load_meta(serial)
            entries = list((meta.get("imap", {}).get(folder, {}) or {}).items())

            total = len(entries)
            entries.sort(key=lambda x: x[1].get("last_fetch", 0), reverse=True)
            slice_ = entries[offset:offset + limit]

            messages = [
                {
                    "uid": uid,
                    "uuid": rec["uuid"],
                    "size": rec["size"],
                    "timestamp": rec["last_fetch"],
                    "hash": rec["hash"],
                }
                for uid, rec in slice_
            ]

            payload = {
                "status": "ok",
                "session_id": session_id,
                "folder": folder,
                "messages": messages,
                "pagination": {
                    "total": total,
                    "current": offset,
                    "next": offset + limit if offset + limit < total else None,
                    "limit": limit,
                },
            }

            self.crypto_reply(
                response_handler="check_mail.cmd_list_mailbox",
                payload=payload,
                session_id=session_id
            )

            if payload.get("status") == "error":
                self.log(f"[EMAIL_CHECK][ERROR] Account {serial} failed: {payload.get('error_code')}")
            else:
                self.log(f"[EMAIL_CHECK] Dispatched callback with {len(messages)} messages (total={total}).")


        except Exception as e:
            self.log(f"[EMAIL_CHECK][CALLBACK-ERROR] {e}")

    def cmd_fetch_new_mail(self, content, packet, identity=None):
        serial = content.get("serial")
        return self._poll_all_accounts_once(serial)

    def _broadcast_swarm_alert(self, msg: str, level: str = "info"):

        payload = {
            "formatted_msg": msg,
            "level": level,
            "timestamp": int(time.time()),
        }

        self.crypto_reply(self._swarm_feed_alert_role, payload)

    def cmd_check_email(self, content, packet, identity=None):
        serial = content.get("serial")
        self.log(f"[EMAIL_CHECK] Checking email for account {serial}...")

        cfg = self.accounts.get(serial)
        if not cfg:
            self.log(f"[EMAIL_CHECK][ERROR] Unknown account serial {serial}")
            return

        result = self._poll_account_once(serial, cfg)
        self.log(f"[EMAIL_CHECK] Email check result for {serial}: {result}")

        # send result back to UI
        session_id = content.get("session_id")
        if session_id:
            self.crypto_reply(
                response_handler="check_mail.cmd_check_email",
                payload={"status": "ok", "serial": serial, "result": result},
                session_id=session_id
            )

    def cmd_retrieve_email(self, content, packet, identity=None):
        try:

            serial = content.get("serial")
            uuid_ = content.get("uuid")
            session_id = content.get("session_id")
            self.log(f"Retrieving email {uuid_} from account {serial}...")
            raw_bytes = self._read_uuid(serial, uuid_)
            parser = EmailParser()
            parsed = parser.parse(raw_bytes)

            payload = {
                "status": "ok",
                "serial": serial,
                "uuid": uuid_,
                "headers": parsed["headers"],
                "subject": parsed["subject"],
                "from": parsed["from"],
                "to": parsed["to"],
                "date": parsed["date"],
                "body_text": parsed["body_text"],
                "body_html": parsed["body_html"],
                "footer": parsed["footer"],
                "attachments": parsed["attachments"],
            }

            self.log(f"Email check complete for email {uuid_} from account {serial}...")
            self.crypto_reply(
                response_handler="check_mail.cmd_retrieve_email",
                payload=payload,
                session_id=session_id
            )


        except Exception as e:
            self.log(error=e)

    def cmd_delete_email(self, content, packet=None, identity=None):
        """
        Accepts either a single UUID or a dictionary of UUIDs for batch deletion.
        Example payloads:
            {"serial": "acct123", "uuid": "abc-123", "remote": True, "folder": "INBOX"}
            {"serial": "acct123", "delete_map": {"abc-123": True, "def-456": False}, "folder": "INBOX"}

        Creates JSON marker files in /mailbox/<serial>/del/
        that the cleanup process can later process (local or remote).
        """
        try:
            serial = content["serial"]
            acct_path = self._acct_paths(serial)
            del_dir = os.path.join(acct_path["cur"].rsplit("/", 1)[0], "del")
            os.makedirs(del_dir, exist_ok=True)

            # Accept dict of ids or a single one
            delete_map = content.get("delete_map")
            if not delete_map:
                uuid_str = content.get("uuid")
                if not uuid_str:
                    self.log("[EMAIL_CHECK][DELETE] ❌ Missing uuid or delete_map.")
                    return
                delete_map = {uuid_str: bool(content.get("remote", False))}

            folder = content.get("folder", "INBOX")
            now = time.time()
            count = 0

            for uuid_str, remote_flag in delete_map.items():
                marker_path = os.path.join(del_dir, f"{uuid_str}.json")
                with open(marker_path, "w") as f:
                    json.dump({
                        "remote": bool(remote_flag),
                        "folder": folder,
                        "timestamp": now
                    }, f)
                count += 1

            self.log(f"[EMAIL_CHECK] 🗳 Staged {count} delete marker(s) for {serial} ({folder})")

            try:
                # Kick off a background cleanup for that account
                self._force_poll_now = True
                self.log(f"[EMAIL_CHECK] Triggered immediate cleanup for {serial}")
            except Exception as e:
                self.log(f"[EMAIL_CHECK][ERROR] Failed to trigger immediate cleanup for {serial}: {e}")

        except Exception as e:
            self.log(error=e, level="ERROR", block="main_try")

    def cmd_remove_account(self, content, packet, identity=None):
        try:
            serial = content["serial"]
            self.accounts.pop(serial, None)
            meta = self._load_meta(serial)
            meta["retired"] = int(time.time())
            self._save_meta(serial, meta)
            return {"status": "ok", "serial": serial}
        except Exception as e:
            self.log(error=e, level="ERROR", block="main_try")

    def cmd_list_accounts(self, content, packet, identity=None):
        """
        Lists all configured email accounts and dispatches the result to Phoenix.
        """
        try:
            session_id = content.get("session_id")
            reposnse_handler=content.get("return_handler")
            out = {}
            for s, cfg in self.accounts.items():
                out[s] = {
                    "incoming_server": cfg.get("incoming_server"),
                    "incoming_port": cfg.get("incoming_port"),
                    "incoming_username": cfg.get("incoming_username"),
                    "encryption": cfg.get("incoming_encryption"),
                    "incoming_password": cfg.get("incoming_password", ""),
                    "folders": cfg.get("folders") or ["INBOX"],
                }

            payload = {
                "status": "ok",
                "accounts": out,
                "session_id": session_id,
            }

            # Dispatch to Phoenix (pre-encryption) — same pattern as retrieve_email
            self.crypto_reply(
                response_handler=reposnse_handler,
                payload=payload,
                session_id=session_id
            )

            self.log(f"[EMAIL_CHECK] 📡 Dispatched {len(out)} account(s) to Phoenix.")

        except Exception as e:
            self.log("[EMAIL_CHECK][LIST-ACCOUNTS][ERROR]", error=e)

    def cmd_nuke_accounts(self, content, packet, identity=None):
        if not content or content.get("confirm") != "NUKE":
            return {"status": "error", "error": "confirm_required", "hint": "send {\"confirm\":\"NUKE\"}"}
        # wipe only under mailbox/
        for child in Path(self.mail_root).glob("*"):
            if child.is_dir():
                for root, dirs, files in os.walk(child, topdown=False):
                    for name in files:
                        try:
                            os.remove(os.path.join(root, name))
                        except Exception:
                            pass
                    for name in dirs:
                        try:
                            os.rmdir(os.path.join(root, name))
                        except Exception:
                            pass
                try:
                    os.rmdir(child)
                except Exception:
                    pass
        return {"status": "ok", "wiped": True}

    def post_boot(self):
        self.log(f"{self.NAME} v{self.AGENT_VERSION} — mailbox collector ready.")

    # --- dynamic config reload ----------------------------------------------
    def _apply_live_config(self, cfg):
        try:
            with self._cfg_lock:
                self.accounts = cfg.get("accounts", self.accounts)
                self._interval = cfg.get("interval_sec", self._interval)
                self.log(f"[EMAIL-CHECK] 🔁 Live config updated — {len(self.accounts)} account(s)")
        except Exception as e:
            self.log("[EMAIL-CHECK][CONFIG-ERROR]", error=e)

    # --- main loop -----------------------------------------------------------
    def worker_pre(self):

        try:
            # === Load and monitor connections file ===
            data = self._load_accounts_file()
            with self._accounts_lock:
                self.accounts = data.get("accounts", {}) or {}

            threading.Thread(target=self._watch_accounts_file, daemon=True).start()

            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def cmd_update_accounts(self, content, packet, identity=None):
        """Update accounts.json.aes from Phoenix (RPC call)."""
        try:
            self.log(f"{content}")
            new_data = content.get("data", {})
            if not isinstance(new_data, dict):
                raise ValueError("Invalid data format — expected dict.")
            new_data = self._normalize_accounts(new_data)
            self._save_accounts_file({"accounts": new_data})
            self.log(f"[EMAIL_CHECK] ✅ Updated accounts.json.aes from Phoenix with {len(new_data)} account(s).")
            return {"status": "ok", "updated": len(new_data)}
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def _poll_loop(self):
        try:

            last_poll = 0
            while self.running:
                now = time.time()
                try:
                    if self._force_poll_now or (now - last_poll >= float(self._poll_interval)):
                        self._force_poll_now = False
                        self.beacon_imap_poll()
                        try:
                            self._safe_poll_all_accounts_once()
                        except Exception as e:
                            self.log(f"[EMAIL_CHECK][POLL-ERROR] {e}", block="_safe_poll_all_accounts_once",
                                     level="ERROR")

                        last_poll = now

                except Exception as loop_error:
                    self.log(f"[EMAIL_CHECK][LOOP-ERROR] {loop_error}", block="_poll_loop", level="ERROR")

                time.sleep(2)

        except Exception as fatal:
            # This will show you the REAL root exception that killed the thread
            self.log(f"[EMAIL_CHECK][FATAL-POLL-LOOP-DEATH] {fatal}", block="_poll_loop", level="ERROR")

    def _safe_poll_all_accounts_once(self):
        with self._accounts_lock:
            self._poll_all_accounts_once()
            
    def worker(self, config=None, identity=None):
        """
        Main polling loop.
        """
        self._emit_beacon()

        if not self.running:
            self.log("[EMAIL-CHECK] Shutdown requested.")
            interruptible_sleep(self, 0.5)
            return

        # live updates
        if isinstance(config, dict) and config != self._last_cfg:
            self._apply_live_config(config)
            self._last_cfg = dict(config)

        # sleep between polls — safe to interrupt on shutdown
        interruptible_sleep(self, self._interval)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()