# License: LGPL-3
"""guard.audit.log / guard.audit.entry: import a gateway audit.jsonl into Odoo
and verify its hash chain with the gateway's exact algorithm.

Verification never trusts the stored ``valid`` flags; it re-reads the raw lines
and re-runs the chain, so an edit made directly in the database is caught too.
"""

import base64
import json

from odoo import api, fields, models
from odoo.exceptions import UserError

from .audit_chain import GENESIS, verify_lines


class GuardAuditLog(models.Model):
    _name = "guard.audit.log"
    _description = "AI Agent Guard — Audit log"
    _order = "create_date desc"

    name = fields.Char(required=True, default="audit.jsonl")
    log_file = fields.Binary("Audit file (.jsonl)", attachment=True)
    log_filename = fields.Char("File name")

    entry_ids = fields.One2many("guard.audit.entry", "log_id", string="Entries")
    entry_count = fields.Integer(compute="_compute_stats", store=True)

    chain_state = fields.Selection(
        [("unknown", "Not verified"), ("ok", "Intact"), ("broken", "Broken")],
        default="unknown",
        string="Chain",
    )
    chain_message = fields.Char(readonly=True)
    chain_head = fields.Char("Chain head", readonly=True)

    @api.depends("entry_ids")
    def _compute_stats(self):
        for rec in self:
            rec.entry_count = len(rec.entry_ids)

    def _raw_lines(self):
        self.ensure_one()
        if not self.log_file:
            raise UserError("Attach the gateway's audit.jsonl file first.")
        raw = base64.b64decode(self.log_file)
        text = raw.decode("utf-8", errors="replace")
        return text.splitlines()

    def action_import(self):
        for rec in self:
            rec.entry_ids.unlink()
            vals = []
            for lineno, line in enumerate(rec._raw_lines(), 1):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = {}
                vals.append(
                    {
                        "log_id": rec.id,
                        "line_no": lineno,
                        "ts": obj.get("ts") or 0.0,
                        "event": obj.get("event") or "",
                        "agent": obj.get("agent") or "",
                        "model_name": obj.get("model") or "",
                        "op": obj.get("op") or "",
                        "hash": obj.get("hash") or "",
                        "prev": obj.get("prev") or "",
                        "raw": line,
                    }
                )
            self.env["guard.audit.entry"].create(vals)
        return self.action_verify()

    def action_verify(self):
        for rec in self:
            ok, n, message, bad = verify_lines(rec._raw_lines())
            rec.chain_state = "ok" if ok else "broken"
            rec.chain_message = message
            # head = hash of the last intact entry (message tail), informational
            rec.chain_head = (
                message.split("head=")[-1] if ok and "head=" in message else ""
            )
            for entry in rec.entry_ids:
                entry.valid = ok or (bad is None) or (entry.line_no < bad)
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Audit chain",
                "message": self.chain_message or "",
                "type": "success" if self.chain_state == "ok" else "danger",
                "sticky": False,
            },
        }


class GuardAuditEntry(models.Model):
    _name = "guard.audit.entry"
    _description = "AI Agent Guard — Audit entry"
    _order = "line_no"

    log_id = fields.Many2one("guard.audit.log", required=True, ondelete="cascade")
    line_no = fields.Integer("Line")
    ts = fields.Float("Timestamp")
    event = fields.Char()
    agent = fields.Char()
    model_name = fields.Char("Model")
    op = fields.Char()
    hash = fields.Char()
    prev = fields.Char()
    raw = fields.Text("Raw line")
    valid = fields.Boolean("Chain OK", default=True)

    genesis = fields.Boolean(compute="_compute_genesis")

    @api.depends("prev")
    def _compute_genesis(self):
        for rec in self:
            rec.genesis = rec.prev == GENESIS
