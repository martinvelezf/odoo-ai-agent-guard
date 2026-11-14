# License: LGPL-3
"""guard.agent: create the dedicated least-privilege Odoo user the gateway logs
in as, mint an API key for it, and show the ready-to-paste MCP env block.

The full API key is shown exactly once, in a transient wizard. Only the last 4
characters are ever stored, matching the gateway's rule of never holding the
secret in the model.
"""

from odoo import api, fields, models
from odoo.exceptions import UserError


class GuardAgent(models.Model):
    _name = "guard.agent"
    _description = "AI Agent Guard — Service agent"

    name = fields.Char("Agent id", required=True, help="Policy agent id, e.g. sales-ops")
    policy_id = fields.Many2one("guard.policy", string="Policy")
    odoo_url = fields.Char("Odoo URL", default="https://erp.example.com")
    odoo_db = fields.Char("Database")
    user_id = fields.Many2one(
        "res.users", string="Service user", domain=[("share", "=", False)]
    )
    user_login = fields.Char(related="user_id.login", string="Login", readonly=True)
    api_key_hint = fields.Char("API key (…last 4)", readonly=True)

    env_block = fields.Text("MCP env block", compute="_compute_env_block", readonly=True)

    @api.depends("name", "odoo_url", "odoo_db", "user_login", "policy_id")
    def _compute_env_block(self):
        for rec in self:
            rec.env_block = (
                '"env": {\n'
                '  "ODOO_URL": "%s", "ODOO_DB": "%s",\n'
                '  "ODOO_USER": "%s", "ODOO_API_KEY": "<the key shown when you minted it>",\n'
                '  "EAG_APPROVAL_SECRET": "<32+ random chars>"\n'
                "}\n"
                "# serve args: --agent %s"
                % (
                    rec.odoo_url or "",
                    rec.odoo_db or "",
                    rec.user_login or "<service login>",
                    rec.name or "<agent>",
                )
            )

    def action_create_user(self):
        """Create a minimal internal user for the gateway to authenticate as.

        It is given no application groups beyond the base internal-user group;
        the admin grants only the record-level ACLs the agent truly needs.
        """
        self.ensure_one()
        if self.user_id:
            raise UserError("A service user is already linked.")
        login = ("ai-gateway-%s" % (self.name or "agent")).lower().replace(" ", "-")
        internal = self.env.ref("base.group_user")
        user = self.env["res.users"].create(
            {
                "name": "AI Gateway (%s)" % self.name,
                "login": login,
                "groups_id": [(6, 0, [internal.id])],
            }
        )
        self.user_id = user.id
        return self._notify(
            "Service user created: %s. Grant it only the ACLs this agent needs."
            % login,
            "success",
        )

    def action_generate_key(self):
        self.ensure_one()
        if not self.user_id:
            raise UserError("Create or link a service user first.")
        from dateutil.relativedelta import relativedelta

        apikeys = self.env["res.users.apikeys"].with_user(self.user_id)
        name = "erp-agent-guard (%s)" % self.name
        expiration = fields.Datetime.now() + relativedelta(years=1)
        try:
            # Odoo 17+: _generate(scope, name, expiration_date)
            key = apikeys._generate("rpc", name, expiration)
        except TypeError:
            # Odoo <=16: _generate(scope, name)
            key = apikeys._generate("rpc", name)
        self.api_key_hint = "…" + key[-4:]
        wizard = self.env["guard.agent.key.wizard"].create(
            {"agent_id": self.id, "api_key": key}
        )
        return {
            "type": "ir.actions.act_window",
            "name": "API key (shown once)",
            "res_model": "guard.agent.key.wizard",
            "res_id": wizard.id,
            "view_mode": "form",
            "target": "new",
        }

    def _notify(self, message, kind):
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {"title": "AI Agent Guard", "message": message, "type": kind},
        }


class GuardAgentKeyWizard(models.TransientModel):
    _name = "guard.agent.key.wizard"
    _description = "AI Agent Guard — API key (shown once)"

    agent_id = fields.Many2one("guard.agent", readonly=True)
    api_key = fields.Char("API key", readonly=True)
