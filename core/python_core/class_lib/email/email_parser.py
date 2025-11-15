# Email parser utility class
from __future__ import annotations
from email import message_from_bytes, message_from_string
from email.policy import default
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import Dict, Any, List, Optional, Tuple
import re

class EmailParser:
    """Parse raw MIME bytes into inert, discrete parts.

    Usage:
        parser = EmailParser()
        parsed = parser.parse(raw_bytes)
    """
    SIG_SEPARATORS = [r"\r\n-- \r\n", r"\r\n--\r\n", r"\n-- \n", r"\n--\n"]
    FOOTER_CANDIDATES = [r"\nRegards[,\s]", r"\nBest[,\s]", r"\nCheers[,\s]", r"\nSincerely[,\s]"]

    def __init__(self, footer_min_block: int = 300) -> None:
        """
        :param footer_min_block: fallback length to consider trailing block a footer
        """
        self.footer_min_block = footer_min_block

    # ---------------------
    # Helpers
    # ---------------------
    @staticmethod
    def _decode_header_value(hdr_value: Optional[str]) -> str:
        if not hdr_value:
            return ""
        parts = decode_header(hdr_value)
        out: List[str] = []
        for bytes_part, enc in parts:
            if isinstance(bytes_part, str):
                out.append(bytes_part)
            else:
                try:
                    out.append(bytes_part.decode(enc or "utf-8", "replace"))
                except Exception:
                    out.append(bytes_part.decode("utf-8", "replace"))
        return "".join(out)

    def _best_footer_guess(self, text: str) -> Tuple[str, str]:
        if not text:
            return "", ""

        # signature separators
        for sep in self.SIG_SEPARATORS:
            parts = re.split(sep, text, maxsplit=1)
            if len(parts) == 2:
                return parts[0].rstrip(), parts[1].lstrip()

        # common sign-offs
        for patt in self.FOOTER_CANDIDATES:
            m = re.search(patt + r".*$", text, flags=re.IGNORECASE | re.DOTALL)
            if m:
                idx = m.start()
                return text[:idx].rstrip(), text[idx:].lstrip()

        # fallback long trailing block
        m = re.search(r"\n{2,}(.{%d,})\Z" % self.footer_min_block, text, flags=re.DOTALL)
        if m:
            idx = m.start(1)
            return text[:idx].rstrip(), text[idx:].lstrip()

        return text, ""

    # ---------------------
    # Core parse
    # ---------------------
    def parse(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Return a dict with inert fields (no binary attachments included)."""
        result: Dict[str, Any] = {
            "headers": "",
            "subject": "",
            "from": "",
            "to": "",
            "date": "",
            "body_text": "",
            "body_html": "",
            "footer": "",
            "attachments": [],
            "raw": "",
        }

        try:
            body_text=None
            msg = message_from_bytes(raw_bytes, policy=default)

            # headers block
            hdr_lines: List[str] = []
            for k, v in msg.items():
                hdr_lines.append(f"{k}: {self._decode_header_value(v)}")
            result["headers"] = "\r\n".join(hdr_lines)

            # simple header fields
            result["subject"] = self._decode_header_value(msg.get("Subject", ""))
            result["from"] = self._decode_header_value(msg.get("From", ""))
            result["to"] = self._decode_header_value(msg.get("To", ""))
            dt = msg.get("Date")
            if dt:
                try:
                    result["date"] = str(parsedate_to_datetime(dt))
                except Exception:
                    result["date"] = dt

            # Walk message parts
            body_text_parts: List[str] = []
            body_html_parts: List[str] = []
            attachments_meta: List[Dict[str, Any]] = []

            if msg.is_multipart():
                for part in msg.walk():
                    # skip container parts
                    if part.is_multipart():
                        continue
                    ctype = part.get_content_type()
                    disp = str(part.get_content_disposition() or "").lower()
                    filename = part.get_filename()

                    # get content safely
                    try:
                        content = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            content = ""
                        else:
                            try:
                                content = payload.decode(part.get_content_charset("utf-8"), "replace")
                            except Exception:
                                content = payload.decode("utf-8", "replace")

                    # attachments metadata only
                    if disp == "attachment" or filename:
                        attachments_meta.append({
                            "filename": filename or "<unknown>",
                            "content_type": ctype,
                            "size": len(part.get_payload(decode=True) or b""),
                        })
                    elif ctype == "text/plain":
                        body_text_parts.append(str(content))
                    elif ctype == "text/html":
                        body_html_parts.append(str(content))
                    else:
                        # inline images or application types recorded as metadata
                        main_type = part.get_content_maintype()
                        if main_type in ("image", "application"):
                            attachments_meta.append({
                                "filename": filename or f"inline-{len(attachments_meta)+1}",
                                "content_type": ctype,
                                "size": len(part.get_payload(decode=True) or b""),
                                "inline": True,
                            })
                        else:
                            # unknown inline type — include as text fallback
                            body_text_parts.append(str(content))
            else:
                # single part message
                ctype = msg.get_content_type()
                try:
                    content = msg.get_content()
                except Exception:
                    payload = msg.get_payload(decode=True)
                    content = (payload.decode(msg.get_content_charset("utf-8"), "replace")
                               if payload else "")
                if ctype == "text/plain":
                    body_text_parts.append(str(content))
                elif ctype == "text/html":
                    body_html_parts.append(str(content))
                else:
                    body_text_parts.append(str(content))

            body_text = "\n\n".join(p.strip() for p in body_text_parts if p and p.strip())
            body_html = "\n\n".join(p.strip() for p in body_html_parts if p and p.strip())

            # footer detection prefers plain text
            body_for_footer = body_text or re.sub(r"<[^>]+>", "", body_html)
            main_body, footer = self._best_footer_guess(body_for_footer)

            result.update({
                "body_text": main_body.strip(),
                "body_html": body_html.strip(),
                "footer": footer.strip(),
                "attachments": attachments_meta,
                "raw": raw_bytes.decode("utf-8", "replace"),
            })

        except Exception as exc:
            result["raw"] = raw_bytes.decode("utf-8", "replace")
            result["body_text"] = ""
            result["body_html"] = ""
            result["footer"] = ""
            result["attachments"] = []
            result["parse_error"] = str(exc)

        # --- Detect and extract generic forwarded or embedded message blocks ---
        try:
            # Typical markers found in bounce or forwarded mails
            markers = [
                r"^Begin forwarded message[:\-]*",
                r"^Forwarded message[:\-]*",
                r"^[-]{5,}\s*Forwarded message\s*[-]{5,}",
                r"^Subject:\s*.+?\nFrom:\s*.+?\nDate:\s*.+?\nTo:\s*.+?\n",
            ]

            forwarded_blocks = []
            for patt in markers:
                m = re.search(patt, body_text, flags=re.IGNORECASE | re.MULTILINE)
                if m:
                    start = m.start()
                    # take everything from marker to end or next signature/footer boundary
                    block = body_text[start:].strip()
                    forwarded_blocks.append(block)
                    break  # first match wins

            for block in forwarded_blocks:
                # Extract lightweight headers from the forwarded text
                f_subject = re.search(r"Subject:\s*(.*)", block, flags=re.IGNORECASE)
                f_from = re.search(r"From:\s*(.*)", block, flags=re.IGNORECASE)
                f_to = re.search(r"To:\s*(.*)", block, flags=re.IGNORECASE)
                f_date = re.search(r"Date:\s*(.*)", block, flags=re.IGNORECASE)

                # Body portion is whatever comes after a blank line following headers
                body_match = re.split(r"\r?\n\r?\n", block, maxsplit=1)
                f_body = body_match[1].strip() if len(body_match) > 1 else ""

                result["attachments"].append({
                    "type": "forwarded",
                    "subject": f_subject.group(1).strip() if f_subject else "",
                    "from": f_from.group(1).strip() if f_from else "",
                    "to": f_to.group(1).strip() if f_to else "",
                    "date": f_date.group(1).strip() if f_date else "",
                    "body": f_body,
                })

        except Exception as e:
            # non-fatal; just note parsing issue if you want to debug later
            result.setdefault("parse_warnings", []).append(f"forwarded_parse_error: {e}")

        return result

    # convenience: parse from str
    def parse_from_string(self, raw: str) -> Dict[str, Any]:
        return self.parse(raw.encode("utf-8", "replace"))
