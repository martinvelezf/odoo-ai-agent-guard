# License: LGPL-3
{
    "name": "AI Agent Guard — Control & Audit",
    "version": "19.0.1.0.0",
    "summary": "Govern and audit AI agents (MCP clients) reaching Odoo through "
    "the erp-agent-guard policy gateway",
    "description": """
AI Agent Guard — Control & Audit
================================

A control panel inside Odoo for teams running the open-source
`erp-agent-guard <https://github.com/martinvelezf/erp-agent-guard>`_ policy
gateway in front of their AI agents (MCP clients).

The gateway itself runs outside Odoo, on purpose — that separation is its trust
boundary. This module does not weaken it. It gives the three things that are
painful to do by hand:

* **Policy editor + YAML export.** Edit per-agent model/field allowlists, PII
  masking, quotas and the approval settings in Odoo, then export the exact
  ``policy.yaml`` the gateway loads.
* **Least-privilege service user + API key.** Create the dedicated Odoo user the
  gateway authenticates as and mint its API key (shown once; only the last four
  characters are stored), with the ready-to-paste MCP ``env`` block.
* **Audit verifier.** Import the gateway's hash-chained ``audit.jsonl`` and
  verify the chain inside Odoo with the identical algorithm the gateway uses, so
  an edited, deleted or reordered line is flagged — including edits made in the
  database.

Pairs with erp-agent-guard; it does not replace Odoo's own access rights.
""",
    "author": "Martin Velez",
    "website": "https://github.com/martinvelezf/erp-agent-guard",
    "license": "LGPL-3",
    "category": "Technical/Security",
    "depends": ["base"],
    "data": [
        "security/guard_security.xml",
        "security/ir.model.access.csv",
        "views/guard_policy_views.xml",
        "views/guard_agent_views.xml",
        "views/guard_audit_views.xml",
        "views/guard_menus.xml",
    ],
    "images": ["static/description/banner.png"],
    "application": True,
    "installable": True,
}
