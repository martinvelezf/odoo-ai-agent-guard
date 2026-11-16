# License: LGPL-3
"""End-to-end flow: policy -> YAML, service user + API key, audit import."""

import base64

from odoo.exceptions import ValidationError
from odoo.tests import TransactionCase, tagged

from .test_audit_chain import HEAD, LINE1, LINE2


@tagged("post_install", "-at_install")
class TestGuardFlow(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.policy = cls.env["guard.policy"].create(
            {
                "name": "test-policy",
                "deny_models": "res.users, hr.*",
                "agent_ids": [
                    (
                        0,
                        0,
                        {
                            "name": "sales-ops",
                            "mode": "read-write",
                            "model_ids": [
                                (
                                    0,
                                    0,
                                    {
                                        "model_name": "res.partner",
                                        "read_fields": "name, email",
                                        "write_fields": "name",
                                        "mask_spec": "email: email",
                                    },
                                )
                            ],
                        },
                    )
                ],
            }
        )

    def test_policy_yaml(self):
        yaml = self.policy.yaml_preview
        self.assertIn("version: 1", yaml)
        self.assertIn('deny: {models: ["res.users", "hr.*"], fields: []}', yaml)
        self.assertIn("  sales-ops:\n    mode: read-write", yaml)
        self.assertIn('read: ["name", "email"]', yaml)
        self.assertIn("mask: {email: email}", yaml)
        action = self.policy.action_download_yaml()
        self.assertEqual(action["type"], "ir.actions.act_url")

    def test_masked_field_not_writable(self):
        with self.assertRaises(ValidationError):
            self.policy.agent_ids.model_ids.write({"write_fields": "name, email"})

    def test_service_user_and_key(self):
        agent = self.env["guard.agent"].create(
            {"name": "sales-ops", "policy_id": self.policy.id, "odoo_db": "db"}
        )
        agent.action_create_user()
        self.assertEqual(agent.user_id.login, "ai-gateway-sales-ops")
        self.assertIn(self.env.ref("base.group_user"), agent.user_id.group_ids)
        self.assertIn('"ODOO_USER": "ai-gateway-sales-ops"', agent.env_block)
        action = agent.action_generate_key()
        wizard = self.env["guard.agent.key.wizard"].browse(action["res_id"])
        self.assertTrue(wizard.api_key)
        self.assertEqual(agent.api_key_hint, "…" + wizard.api_key[-4:])
        key = self.env["res.users.apikeys"].sudo().search(
            [("user_id", "=", agent.user_id.id)]
        )
        self.assertEqual(len(key), 1)

    def _log(self, lines):
        data = base64.b64encode("\n".join(lines).encode())
        return self.env["guard.audit.log"].create({"log_file": data})

    def test_audit_import_intact(self):
        log = self._log([LINE1, LINE2])
        log.action_import()
        self.assertEqual(log.chain_state, "ok")
        self.assertEqual(log.entry_count, 2)
        self.assertEqual(log.chain_head, HEAD[:16])
        self.assertTrue(all(log.entry_ids.mapped("valid")))
        self.assertTrue(log.entry_ids[0].genesis)

    def test_audit_import_reordered(self):
        log = self._log([LINE2, LINE1])
        log.action_import()
        self.assertEqual(log.chain_state, "broken")
        self.assertFalse(any(log.entry_ids.mapped("valid")))
