"""Pure, dependency-free re-implementation of the erp-agent-guard audit chain.

This MUST stay byte-for-byte compatible with ``erp_agent_guard.audit`` in the
gateway: the canonicalisation and hashing here is what lets Odoo verify a log
the gateway wrote. No Odoo import, so it can be unit-tested on its own.

Gateway reference (erp_agent_guard/audit.py):
    _canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, default=str).encode()
    _hash      = sha256 over the entry with the "hash" key removed
    each line carries  prev  (hash of the previous line) and  hash
    GENESIS = "0" * 64
"""

from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64


def canonical(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


def verify_lines(lines):
    """Replicate erp-agent-guard's ``verify_audit`` over an iterable of text lines.

    Returns ``(ok, n_checked, message, first_bad_lineno)``.
    ``first_bad_lineno`` is 1-based (counting every physical line, blank or not)
    or ``None`` when the chain is intact.
    """
    prev = GENESIS
    n = 0
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            return False, n, "line %d: not valid JSON" % lineno, lineno
        if entry.get("prev") != prev:
            return (
                False,
                n,
                "line %d: chain broken (prev does not match previous hash)" % lineno,
                lineno,
            )
        if entry.get("hash") != entry_hash(entry):
            return (
                False,
                n,
                "line %d: content hash mismatch (line was edited)" % lineno,
                lineno,
            )
        prev = entry["hash"]
        n += 1
    return True, n, "%d entries, chain intact, head=%s" % (n, prev[:16]), None
