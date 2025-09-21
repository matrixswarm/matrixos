# Minimal size/nesting/field-count guard for inbound packets.
# Call guard_packet_size(pk, log=self.log) at the TOP of incoming_packet_acl_check.

import json

# Tunables — tighten/loosen as needed
MAX_PACKET_BYTES   = 128 * 1024   # hard ceiling on whole JSON packet
MAX_CONTENT_BYTES  = 96 * 1024    # ceiling for pk["content"] subtree
MAX_HANDLER_LEN    = 128          # max chars for handler
MAX_FIELDS_TOTAL   = 256          # upper bound on total keys/elements
MAX_NESTED_DEPTH   = 10           # stop deeply nested bombs
MAX_STRING_FIELD   = 32 * 1024    # max bytes for any single string field

def _byte_len(obj) -> int:
    try:
        return len(json.dumps(obj, ensure_ascii=False).encode("utf-8"))
    except Exception:
        return float("inf")  # fail closed

def _count_fields(obj, depth=0) -> int:
    if depth > MAX_NESTED_DEPTH:
        return float("inf")
    if isinstance(obj, dict):
        c = 0
        for v in obj.values():
            c += 1
            c += _count_fields(v, depth + 1)
        return c
    if isinstance(obj, list):
        c = 0
        for v in obj:
            c += _count_fields(v, depth + 1)
        return c
    return 0

def _validate_strings(obj, depth=0) -> bool:
    if depth > MAX_NESTED_DEPTH:
        return False
    if isinstance(obj, dict):
        for v in obj.values():
            if not _validate_strings(v, depth + 1):
                return False
    elif isinstance(obj, list):
        for v in obj:
            if not _validate_strings(v, depth + 1):
                return False
    elif isinstance(obj, str):
        if len(obj.encode("utf-8")) > MAX_STRING_FIELD:
            return False
    return True

def guard_packet_size(pk: dict, log=print) -> bool:
    # 1) Whole-packet size
    pkt_bytes = _byte_len(pk)
    if pkt_bytes > MAX_PACKET_BYTES:
        log(f"[ACL] Packet too large: {pkt_bytes} > {MAX_PACKET_BYTES}")
        return False

    # 2) Handler sanity
    handler = pk.get("handler")
    if not isinstance(handler, str) or not handler or len(handler) > MAX_HANDLER_LEN:
        log(f"[ACL] Bad handler length: {len(handler) if isinstance(handler, str) else 'n/a'}")
        return False

    # 3) Content subtree budget
    content = pk.get("content", {})
    if _byte_len(content) > MAX_CONTENT_BYTES:
        log("[ACL] Content too large")
        return False

    # 4) Total fields + nesting depth
    total_fields = _count_fields(pk)
    if total_fields > MAX_FIELDS_TOTAL:
        log(f"[ACL] Too many fields: {total_fields} > {MAX_FIELDS_TOTAL}")
        return False

    # 5) Any string unreasonably big / excessive nesting
    if not _validate_strings(pk):
        log("[ACL] Oversized string field or excessive nesting depth")
        return False

    return True