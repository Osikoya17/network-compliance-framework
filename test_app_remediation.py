"""Endpoint regression tests; no live SSH connections or config writes."""
import unittest
from unittest.mock import patch

from jinja2 import TemplateNotFound

import app as webapp
from compliance.engine import ComplianceResult


def check(rule="Unused ports shutdown", interface="Ethernet0/2", status="FAIL", expected=True):
    return ComplianceResult(rule, status, expected, False, interface=interface)


class RemediationScopeTests(unittest.TestCase):
    def setUp(self):
        self.device = {"name": "SW1-ACCESS", "collection_method": "ssh"}
        self.before = [check(), check(interface="Ethernet0/3"), check("NTP configured", None)]
        self.after = [check(status="PASS"), self.before[1], self.before[2]]
        self.state = {"SW1-ACCESS": {"last_scan": {"results": self.before, "score": 0}}}
        self.client = webapp.app.test_client()
        for name, value in (
            ("STATE", self.state),
            ("_device_by_name", lambda name: self.device),
            ("load_baseline", lambda: {}),
        ):
            patcher = patch.object(webapp, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.applier = self.enterContext(patch.object(webapp, "LiveRemediationApplier"))
        self.scan = self.enterContext(patch.object(webapp, "scan_device", return_value={
            "results": self.after, "score": 33.33,
        }))
        self.generator = self.enterContext(patch.object(
            webapp.RemediationGenerator, "generate_for_violation",
            wraps=webapp.RemediationGenerator().generate_for_violation,
        ))

    def post(self, **scope):
        return self.client.post("/remediate/SW1-ACCESS", json={"live": True, **scope})

    def test_row_applies_only_matching_interface_and_keeps_other_failures(self):
        data = self.post(rule="Unused ports shutdown", interface="Ethernet0/2").get_json()
        self.generator.assert_called_once_with(self.before[0])
        self.applier.return_value.apply.assert_called_once()
        commands = self.applier.return_value.apply.call_args.args[0]
        self.assertIn("interface Ethernet0/2", commands)
        self.assertNotIn("Ethernet0/3", commands)
        self.assertEqual(data["applied"], [{"rule": "Unused ports shutdown", "interface": "Ethernet0/2"}])
        self.assertEqual([r["status"] for r in data["after"]["results"]], ["PASS", "FAIL", "FAIL"])
        self.assertIs(self.state["SW1-ACCESS"]["last_scan"]["results"], self.after)
        self.scan.assert_called_once_with(self.device, {})

    def test_explicit_all_uses_remaining_failures_after_row_fix(self):
        self.post(rule="Unused ports shutdown", interface="Ethernet0/2")
        self.generator.reset_mock()
        self.applier.return_value.apply.reset_mock()
        self.scan.return_value = {"results": [check(status="PASS"), check(interface="Ethernet0/3", status="PASS"), check("NTP configured", None, "PASS")], "score": 100}
        response = self.post(all=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.generator.call_count, 2)
        self.assertEqual(self.applier.return_value.apply.call_count, 2)
        self.assertEqual(response.get_json()["applied"], [
            {"rule": "Unused ports shutdown", "interface": "Ethernet0/3"},
            {"rule": "NTP configured", "interface": None},
        ])

    def test_missing_or_invalid_scope_never_applies(self):
        for scope in ({}, {"all": False}, {"all": "true"}, {"all": 1}, {"rule": None, "all": True}):
            with self.subTest(scope=scope):
                self.assertEqual(self.post(**scope).status_code, 400)
        self.applier.assert_not_called()
        self.generator.assert_not_called()
        self.scan.assert_not_called()

    def test_no_matching_failure_returns_400(self):
        for scope in (
            {"rule": "Unused ports shutdown", "interface": "Ethernet0/9"},
            {"rule": "Unused ports shutdown", "interface": None},
            {"rule": "SSH enabled", "interface": "Ethernet0/2"},
        ):
            with self.subTest(scope=scope):
                response = self.post(**scope)
                self.assertEqual(response.status_code, 400)
                self.assertIn("no matching failing check", response.get_json()["error"])
        self.applier.assert_not_called()
        self.generator.assert_not_called()

    def test_pass_row_is_not_remediated(self):
        self.before[0].status = "PASS"
        self.assertEqual(self.post(rule=self.before[0].rule, interface=self.before[0].interface).status_code, 400)
        self.applier.assert_not_called()

    def test_null_interface_matches_only_whole_device(self):
        self.before.append(check("NTP configured", "Ethernet0/2"))
        response = self.post(rule="NTP configured", interface=None)
        self.assertEqual(response.status_code, 200)
        self.generator.assert_called_once_with(self.before[2])
        self.assertEqual(response.get_json()["applied"], [{"rule": "NTP configured", "interface": None}])

    def test_rule_takes_precedence_over_all(self):
        response = self.post(rule="Unused ports shutdown", interface="Ethernet0/2", all=True)
        self.assertEqual(response.status_code, 200)
        self.generator.assert_called_once_with(self.before[0])

    def test_live_requires_ssh(self):
        self.device["collection_method"] = "file"
        response = self.post(rule="Unused ports shutdown", interface="Ethernet0/2")
        self.assertEqual(response.status_code, 400)
        self.applier.assert_not_called()
        self.generator.assert_not_called()
        self.scan.assert_not_called()

    def test_maximum_mac_uses_shared_template_for_selected_interface(self):
        self.before[:] = [check("Maximum MAC addresses", expected=3), check("Maximum MAC addresses", "Ethernet0/3")]
        response = self.post(rule="Maximum MAC addresses", interface="Ethernet0/2")
        self.assertEqual(response.status_code, 200)
        commands = self.applier.return_value.apply.call_args.args[0]
        self.assertIn("interface Ethernet0/2", commands)
        self.assertIn("switchport port-security maximum 3", commands)
        self.assertNotIn("Ethernet0/3", commands)
        self.assertEqual(response.get_json()["applied"], [{"rule": "Maximum MAC addresses", "interface": "Ethernet0/2"}])

    def test_unsupported_missing_and_empty_templates_are_explicit(self):
        for generated in (None, TemplateNotFound("missing.j2"), "  \n"):
            with self.subTest(generated=generated):
                self.state["SW1-ACCESS"]["last_scan"]["results"] = self.before
                self.applier.return_value.apply.reset_mock()
                with patch.object(webapp.RemediationGenerator, "generate_for_violation") as generator:
                    generator.side_effect = generated if isinstance(generated, Exception) else None
                    generator.return_value = generated
                    response = self.post(rule="Unused ports shutdown", interface="Ethernet0/2")
                self.assertEqual(response.status_code, 200)
                data = response.get_json()
                self.assertEqual(data["applied"], [])
                self.assertEqual(data["skipped"], [{
                    "rule": "Unused ports shutdown", "interface": "Ethernet0/2",
                    "reason": "no automated fix for Unused ports shutdown",
                }])
                self.applier.return_value.apply.assert_not_called()

    def test_unmapped_rule_returns_clear_message(self):
        self.before[:] = [check("Hostname correct", None)]
        response = self.post(rule="Hostname correct", interface=None)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["skipped"][0]["reason"], "no automated fix for Hostname correct")
        self.applier.return_value.apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
