# AI Agent Guard — Control & Audit

Companion Odoo module for the [erp-agent-guard](https://github.com/martinvelezf/erp-agent-guard)
policy gateway. It does **not** run the gateway inside Odoo (the gateway's
out-of-process isolation is its trust boundary); it gives you the control plane:

- **Policies** — edit per-agent allowlists, masking, quotas and approval, then
  **export the exact `policy.yaml`** the gateway consumes.
- **Service agents** — create the least-privilege Odoo user the gateway logs in
  as and mint its API key (shown once; only the last 4 chars stored).
- **Audit logs** — import the gateway's `audit.jsonl` and **verify the hash
  chain inside Odoo** with the gateway's exact algorithm (tamper-evident).

License: LGPL-3. Pairs with, and does not replace, Odoo's own access rights.

## Tests

`tests/test_audit_chain.py` pins the verifier to a frozen golden vector produced
by the gateway, so Odoo cannot silently drift from the gateway's hashing.
