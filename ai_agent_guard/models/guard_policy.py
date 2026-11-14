# License: LGPL-3
"""guard.policy and its children: edit an erp-agent-guard policy in Odoo and
export the exact ``policy.yaml`` the gateway consumes.

The YAML is emitted by hand (no PyYAML dependency on the Odoo side) for the
fixed schema the gateway validates. Keep the output aligned with
``examples/policy.yaml`` in the gateway repo.
"""

from odoo import api, fields, models
from odoo.exceptions import ValidationError


def _split(value):
    """A comma/space/newline separated char field -> clean list, order kept."""
    if not value:
        return []
    out = []
    for chunk in value.replace(",", "\n").split("\n"):
        item = chunk.strip()
        if item and item not in out:
            out.append(item)
    return out


def _yaml_list(items):
    return "[" + ", ".join('"%s"' % i for i in items) + "]"


class GuardPolicy(models.Model):
    _name = "guard.policy"
    _description = "AI Agent Guard — Policy"

    name = fields.Char(required=True, default="policy")
    active = fields.Boolean(default=True)

    default_mode = fields.Selection(
        [("read-only", "Read only"), ("read-write", "Read / write")],
        string="Default mode",
        default="read-only",
        required=True,
    )
    default_max_records = fields.Integer("Default max records", default=50)
    default_calls_per_minute = fields.Integer("Calls / minute", default=30)
    default_writes_per_day = fields.Integer("Writes / day", default=20)

    deny_models = fields.Char(
        "Extra deny models",
        help="Comma or newline separated, e.g. res.users, hr.*. "
        "These add to the gateway's built-in deny list.",
    )
    deny_fields = fields.Char(
        "Extra deny fields", help="Comma or newline separated, e.g. *_token."
    )

    approval_required = fields.Boolean("Require approval", default=True)
    approval_secret_env = fields.Char(
        "Approval secret env var", default="EAG_APPROVAL_SECRET"
    )
    approval_ttl_seconds = fields.Integer("Approval TTL (s)", default=900)

    audit_path = fields.Char("Audit log path", default="audit.jsonl")
    proposals_path = fields.Char("Proposals path", default="proposals.json")

    agent_ids = fields.One2many("guard.policy.agent", "policy_id", string="Agents")

    yaml_preview = fields.Text("policy.yaml", compute="_compute_yaml", readonly=True)

    @api.constrains("approval_ttl_seconds", "default_max_records")
    def _check_positive(self):
        for rec in self:
            if rec.approval_ttl_seconds < 0:
                raise ValidationError("Approval TTL cannot be negative.")
            if rec.default_max_records < 1:
                raise ValidationError("Default max records must be at least 1.")

    @api.depends(
        "default_mode",
        "default_max_records",
        "default_calls_per_minute",
        "default_writes_per_day",
        "deny_models",
        "deny_fields",
        "approval_required",
        "approval_secret_env",
        "approval_ttl_seconds",
        "audit_path",
        "proposals_path",
        "agent_ids",
        "agent_ids.name",
        "agent_ids.mode",
        "agent_ids.model_ids",
        "agent_ids.model_ids.model_name",
        "agent_ids.model_ids.read_fields",
        "agent_ids.model_ids.write_fields",
        "agent_ids.model_ids.create_fields",
        "agent_ids.model_ids.mask_spec",
    )
    def _compute_yaml(self):
        for rec in self:
            rec.yaml_preview = rec._to_yaml()

    def _to_yaml(self):
        self.ensure_one()
        L = []
        L.append("version: 1")
        L.append(
            "defaults: {mode: %s, max_records: %d, quota: {calls_per_minute: %d, writes_per_day: %d}}"
            % (
                self.default_mode,
                self.default_max_records,
                self.default_calls_per_minute,
                self.default_writes_per_day,
            )
        )
        deny_models = _split(self.deny_models)
        deny_fields = _split(self.deny_fields)
        if deny_models or deny_fields:
            L.append(
                "deny: {models: %s, fields: %s}"
                % (_yaml_list(deny_models), _yaml_list(deny_fields))
            )
        L.append("agents:")
        if not self.agent_ids:
            L.append("  {}")
        for agent in self.agent_ids:
            L.append("  %s:" % agent.name)
            if agent.mode:
                L.append("    mode: %s" % agent.mode)
            L.append("    models:")
            if not agent.model_ids:
                L.append("      {}")
            for m in agent.model_ids:
                L.append("      %s:" % m.model_name)
                reads = _split(m.read_fields)
                writes = _split(m.write_fields)
                creates = _split(m.create_fields)
                if reads:
                    L.append("        read: %s" % _yaml_list(reads))
                if writes:
                    L.append("        write: %s" % _yaml_list(writes))
                if creates:
                    L.append("        create: %s" % _yaml_list(creates))
                mask = m._mask_pairs()
                if mask:
                    inner = ", ".join("%s: %s" % (f, s) for f, s in mask)
                    L.append("        mask: {%s}" % inner)
        L.append(
            "approval: {required: %s, secret_env: %s, ttl_seconds: %d}"
            % (
                "true" if self.approval_required else "false",
                self.approval_secret_env or "EAG_APPROVAL_SECRET",
                self.approval_ttl_seconds,
            )
        )
        L.append("audit: {path: %s}" % (self.audit_path or "audit.jsonl"))
        L.append("proposals: {path: %s}" % (self.proposals_path or "proposals.json"))
        return "\n".join(L) + "\n"

    def action_download_yaml(self):
        """Offer the rendered policy.yaml as a download via a fresh attachment."""
        self.ensure_one()
        import base64

        attachment = self.env["ir.attachment"].create(
            {
                "name": "policy.yaml",
                "type": "binary",
                "datas": base64.b64encode(self._to_yaml().encode("utf-8")),
                "res_model": self._name,
                "res_id": self.id,
                "mimetype": "text/yaml",
            }
        )
        return {
            "type": "ir.actions.act_url",
            "url": "/web/content/%d?download=true" % attachment.id,
            "target": "self",
        }


class GuardPolicyAgent(models.Model):
    _name = "guard.policy.agent"
    _description = "AI Agent Guard — Policy agent"

    policy_id = fields.Many2one("guard.policy", required=True, ondelete="cascade")
    name = fields.Char("Agent id", required=True, help="e.g. sales-ops")
    mode = fields.Selection(
        [("read-only", "Read only"), ("read-write", "Read / write")],
        help="Leave empty to inherit the policy default.",
    )
    model_ids = fields.One2many(
        "guard.policy.model", "agent_id", string="Models"
    )


class GuardPolicyModel(models.Model):
    _name = "guard.policy.model"
    _description = "AI Agent Guard — Policy model grant"

    agent_id = fields.Many2one("guard.policy.agent", required=True, ondelete="cascade")
    model_name = fields.Char("Model", required=True, help="e.g. res.partner")
    read_fields = fields.Char("Read fields")
    write_fields = fields.Char("Write fields")
    create_fields = fields.Char("Create fields")
    mask_spec = fields.Text(
        "Mask",
        help="One 'field: strategy' per line. Strategies: email, last4, "
        "initials, hash, redact.",
    )

    _MASK_STRATEGIES = {"email", "last4", "initials", "hash", "redact"}

    def _mask_pairs(self):
        self.ensure_one()
        pairs = []
        for line in (self.mask_spec or "").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            field, strategy = (p.strip() for p in line.split(":", 1))
            if field and strategy:
                pairs.append((field, strategy))
        return pairs

    @api.constrains("mask_spec", "write_fields")
    def _check_mask(self):
        for rec in self:
            writes = set(_split(rec.write_fields))
            for field, strategy in rec._mask_pairs():
                if strategy not in rec._MASK_STRATEGIES:
                    raise ValidationError(
                        "Unknown mask strategy %r for field %r. Use one of: %s"
                        % (strategy, field, ", ".join(sorted(rec._MASK_STRATEGIES)))
                    )
                # Same rule the gateway enforces: an agent cannot overwrite a
                # field it is only allowed to see masked.
                if field in writes:
                    raise ValidationError(
                        "Field %r is masked and cannot also be writable "
                        "(the agent cannot see what it overwrites)." % field
                    )
