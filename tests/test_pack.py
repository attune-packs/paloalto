from __future__ import annotations

import io
import json
import os
import re
import sys
import types
import unittest
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import panos_client as client

SOURCE_REVISION = "efdc0db1dc96f94c4288a9c2ff227f2c9d0ee05e"


def response(xml: str) -> ET.Element:
    return ET.fromstring(xml)


SUCCESS = response('<response status="success"><result /></response>')
FOUND = response('<response status="success"><result><entry name="web"><ip-netmask>192.0.2.1</ip-netmask></entry></result></response>')


class FakeClient:
    def __init__(self, replies=None):
        self.calls = []
        self.replies = list(replies or [])

    def _reply(self):
        return self.replies.pop(0) if self.replies else SUCCESS

    def config(self, action, xpath, element=None):
        self.calls.append(("config", action, xpath, element))
        return self._reply()

    def request(self, request_type, **params):
        self.calls.append(("request", request_type, params))
        return self._reply()

    def op(self, command):
        self.calls.append(("op", command))
        return self._reply()


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        object_actions = {
            f"{kind}_{verb}"
            for kind in ("address_object", "address_group", "service_object", "service_group")
            for verb in ("get", "create", "update", "delete")
        }
        expected = object_actions | {
            "security_rule_get", "security_rule_create", "security_rule_update", "security_rule_delete",
            "dynamic_address_register", "dynamic_address_unregister", "pending_changes", "system_info",
            "job_status", "commit", "commit_all",
        }
        self.assertEqual(expected, set(self.actions))

    def test_actions_use_flat_stdin_json_key_refs_and_structured_output(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"paloalto.{name}",
                    "runner_type": "python",
                    "runtime_version": '">=3.10"',
                    "entry_point": "paloalto_action.py",
                    "parameter_delivery": "stdin",
                    "parameter_format": "json",
                    "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: pack\.paloalto\.credentials[^\n]*\}")
                self.assertRegex(text, r"target_type: \{[^\n]*required: true")
                for field in ("operation", "target_type", "changed", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, r"(?m)^  (api_key|username|password|base_url):")
                self.assertNotIn("type: object, required: true", text)

    def test_destructive_and_replacement_actions_have_confirmation_contracts(self):
        for name, text in self.actions.items():
            if name.endswith(("_delete", "_update")):
                self.assertRegex(text, r"(?m)^  confirm_name: \{[^\n]*required: true")
        self.assertIn("confirm:", self.actions["dynamic_address_unregister"])
        self.assertIn("confirm:", self.actions["commit"])
        self.assertIn("confirm:", self.actions["commit_all"])

    def test_source_license_and_no_undeclared_runtime_dependencies(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn(f'source_revision: "{SOURCE_REVISION}"', pack)
        self.assertIn('source_version: "1.0.0"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn(SOURCE_REVISION, (ROOT / "NOTICE").read_text(encoding="utf-8"))
        self.assertIn(SOURCE_REVISION, (ROOT / "SOURCE.md").read_text(encoding="utf-8"))
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertFalse(any(line.strip() and not line.startswith("#") for line in requirements.splitlines()))


class ValidationTests(unittest.TestCase):
    def test_xml_parser_rejects_dtd_entities_oversize_and_invalid_xml(self):
        malicious = b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><response>&secret;</response>'
        with self.assertRaisesRegex(client.PanosPackError, "DTD or entity"):
            client._parse_xml(malicious)
        with self.assertRaisesRegex(client.PanosPackError, "8 MiB"):
            client._parse_xml(b"x" * (client.MAX_RESPONSE_BYTES + 1))
        with self.assertRaisesRegex(client.PanosPackError, "invalid XML"):
            client._parse_xml(b"<response>")

    def test_xpath_components_reject_quotes_predicates_and_controls(self):
        bad_names = ["bad'name", 'bad\"name', "entry[1]", "../shared", "bad/name", "bad\nname"]
        for name in bad_names:
            with self.subTest(name=name), self.assertRaises(client.PanosPackError):
                client._object_xpath({"scope": "local", "name": name}, "firewall", "address_object")

    def test_firewall_and_panorama_scope_and_policy_placement(self):
        root, location = client._scope_root({"scope": "local", "vsys": "vsys2"}, "firewall")
        self.assertIn("/vsys/entry[@name='vsys2']", root)
        self.assertEqual("local", location["scope"])
        root, location = client._scope_root({"scope": "device_group", "device_group": "branch"}, "panorama")
        self.assertIn("/device-group/entry[@name='branch']", root)
        self.assertEqual("branch", location["device_group"])
        path, _, _ = client._security_xpath(
            {"scope": "shared", "policy_position": "pre", "name": "allow-web"}, "panorama"
        )
        self.assertEqual("/config/shared/pre-rulebase/security/rules", path)
        with self.assertRaisesRegex(client.PanosPackError, "requires shared or device_group"):
            client._scope_root({"scope": "local"}, "panorama")
        with self.assertRaisesRegex(client.PanosPackError, "local policy_position"):
            client._security_xpath(
                {"scope": "local", "policy_position": "pre", "name": "allow-web"}, "firewall"
            )
        with self.assertRaisesRegex(client.PanosPackError, "does not accept vsys"):
            client._scope_root({"scope": "shared", "vsys": "vsys1"}, "panorama")

    def test_payload_builders_escape_xml_in_text_and_constrain_rule_fields(self):
        entry = client._build_object("address_group", {
            "group_type": "dynamic", "filter": "'prod' and \"web\"", "description": "a < b & c", "tags": []
        }, "dynamic-web")
        xml = client._element_xml(entry)
        self.assertIn("a &lt; b &amp; c", xml)
        self.assertIn("\"web\"", xml)
        with self.assertRaisesRegex(client.PanosPackError, "must be one of"):
            client._build_security_rule({
                "from_zones": ["trust"], "to_zones": ["untrust"], "sources": ["any"],
                "destinations": ["any"], "applications": ["web-browsing"], "services": ["application-default"],
                "action": "execute-shell",
            }, "bad-rule")

    def test_address_group_static_dynamic_fields_are_mutually_exclusive(self):
        with self.assertRaisesRegex(client.PanosPackError, "do not accept filter"):
            client._build_object("address_group", {"group_type": "static", "members": [], "filter": "x"}, "group")
        with self.assertRaisesRegex(client.PanosPackError, "do not accept members"):
            client._build_object("address_group", {"group_type": "dynamic", "members": ["host"], "filter": "x"}, "group")


class TransportTests(unittest.TestCase):
    def credential(self, **updates):
        value = {
            "base_url": "https://pa.example.invalid:8443",
            "target_type": "firewall",
            "api_key": "TOP-SECRET-KEY",
        }
        value.update(updates)
        return value

    def test_credentials_require_https_matching_target_verified_tls_and_one_auth_mode(self):
        bad = [
            self.credential(base_url="http://pa.invalid"),
            self.credential(base_url="https://user:pass@pa.invalid"),
            self.credential(base_url="https://pa.invalid/api"),
            self.credential(target_type="panorama"),
            self.credential(verify_tls=False),
            self.credential(username="admin", password="secret"),
            {"base_url": "https://pa.invalid", "target_type": "firewall", "username": "admin"},
        ]
        for credential in bad:
            with self.subTest(credential=credential), self.assertRaises(client.PanosPackError):
                client.PanosClient(credential, "firewall", 10)

    def test_api_key_uses_header_not_url_or_form_and_redirects_are_disabled(self):
        panos = client.PanosClient(self.credential(), "firewall", 10)
        redirect = next(handler for handler in panos.opener.handlers if isinstance(handler, client._NoRedirect))

        class Opened:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                return b'<response status="success"><result /></response>'

        panos.opener = mock.Mock()
        panos.opener.open.return_value = Opened()
        panos.request("op", cmd="<show><system><info /></system></show>")
        request = panos.opener.open.call_args.args[0]
        form = urllib.parse.parse_qs(request.data.decode())
        self.assertEqual("TOP-SECRET-KEY", request.get_header("X-pan-key"))
        self.assertNotIn("key", form)
        self.assertNotIn("TOP-SECRET-KEY", request.full_url)
        self.assertIsNone(redirect.redirect_request(None, None, 302, "Found", {}, "https://other.invalid"))

    def test_bootstrap_key_stays_in_memory_and_transport_errors_are_redacted(self):
        credential = {
            "base_url": "https://pa.invalid", "target_type": "firewall",
            "username": "admin", "password": "DO-NOT-ECHO",
        }
        key_response = response('<response status="success"><result><key>GENERATED-SECRET</key></result></response>')
        with mock.patch.object(client.PanosClient, "_post", return_value=key_response):
            panos = client.PanosClient(credential, "firewall", 10)
        self.assertEqual("GENERATED-SECRET", panos.api_key)
        panos.opener = mock.Mock()
        panos.opener.open.side_effect = urllib.error.URLError("GENERATED-SECRET DO-NOT-ECHO")
        with self.assertRaises(client.PanosPackError) as caught:
            panos.request("op", cmd="<show />")
        self.assertNotIn("GENERATED-SECRET", str(caught.exception))
        self.assertNotIn("DO-NOT-ECHO", str(caught.exception))

    def test_api_error_body_is_not_propagated(self):
        panos = client.PanosClient(self.credential(), "firewall", 10)

        class Opened:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                return b'<response status="error" code="7"><msg>TOP-SECRET-KEY</msg></response>'

        panos.opener = mock.Mock()
        panos.opener.open.return_value = Opened()
        with self.assertRaises(client.PanosPackError) as caught:
            panos.request("config", action="get", xpath="/config")
        self.assertEqual("PAN-OS API returned an error code 7", str(caught.exception))


class OperationTests(unittest.TestCase):
    def test_create_checks_existence_then_mutates_exactly_once(self):
        fake = FakeClient([SUCCESS, SUCCESS])
        data, changed, location = client._object_action(fake, "address_object_create", {
            "scope": "local", "name": "web", "address_type": "ip-netmask",
            "value": "192.0.2.1", "tags": [],
        }, "firewall")
        self.assertTrue(changed)
        self.assertEqual("local", location["scope"])
        self.assertEqual(["get", "set"], [call[1] for call in fake.calls])
        self.assertEqual(1, sum(call[1] in {"set", "edit", "delete"} for call in fake.calls))
        self.assertTrue(data["candidate_config"])

    def test_update_delete_require_confirmation_before_mutation(self):
        for operation in ("address_object_update", "address_object_delete"):
            fake = FakeClient([FOUND])
            params = {
                "scope": "local", "name": "web", "address_type": "ip-netmask",
                "value": "192.0.2.2", "tags": [], "confirm_name": "wrong",
            }
            with self.subTest(operation=operation), self.assertRaisesRegex(client.PanosPackError, "confirm_name"):
                client._object_action(fake, operation, params, "firewall")
            self.assertEqual(0, len(fake.calls))

    def test_security_rule_build_and_panorama_candidate_path(self):
        fake = FakeClient([SUCCESS, SUCCESS])
        params = {
            "scope": "device_group", "device_group": "branch", "policy_position": "post",
            "name": "allow-web", "from_zones": ["trust"], "to_zones": ["untrust"],
            "sources": ["web-src"], "destinations": ["web-dst"], "source_users": ["any"],
            "applications": ["web-browsing"], "services": ["application-default"],
            "categories": ["any"], "action": "allow", "tags": [],
        }
        _, changed, location = client._security_action(fake, "security_rule_create", params, "panorama")
        self.assertTrue(changed)
        self.assertEqual("post", location["policy_position"])
        self.assertIn("/device-group/entry[@name='branch']/post-rulebase/security/rules", fake.calls[0][2])
        entry = fake.calls[1][3]
        self.assertEqual("allow", entry.findtext("action"))
        self.assertEqual("application-default", entry.findtext("service/member"))

    def test_security_rule_update_rejects_fields_it_cannot_preserve(self):
        existing = response('<response status="success"><result><entry name="allow-web"><from><member>trust</member></from><option><disable-server-response-inspection>yes</disable-server-response-inspection></option></entry></result></response>')
        fake = FakeClient([existing])
        params = {
            "scope": "local", "policy_position": "local", "name": "allow-web",
            "confirm_name": "allow-web", "from_zones": ["trust"], "to_zones": ["untrust"],
            "sources": ["any"], "destinations": ["any"], "applications": ["web-browsing"],
            "services": ["application-default"], "action": "allow", "tags": [],
        }
        with self.assertRaisesRegex(client.PanosPackError, "safely representable"):
            client._security_action(fake, "security_rule_update", params, "firewall")
        self.assertEqual(1, len(fake.calls))

    def test_dynamic_registration_supports_panorama_and_explicit_serial(self):
        direct = FakeClient()
        client._dynamic_address(direct, "dynamic_address_register", {
            "ip_addresses": ["192.0.2.0/24"], "tags": ["blocked"],
        }, "panorama")
        self.assertNotIn("target", direct.calls[0][2])
        fake = FakeClient()
        data, changed, meta = client._dynamic_address(fake, "dynamic_address_register", {
            "ip_addresses": ["2001:0db8::1"], "tags": ["blocked"],
            "managed_device_serial": "0123456789",
        }, "panorama")
        self.assertTrue(changed)
        self.assertEqual(["2001:db8::1"], data["ip_addresses"])
        self.assertEqual("0123456789", meta["managed_device_serial"])
        self.assertEqual("0123456789", fake.calls[0][2]["target"])
        self.assertIn("<register>", fake.calls[0][2]["cmd"])
        with self.assertRaisesRegex(client.PanosPackError, "UNREGISTER"):
            client._dynamic_address(FakeClient(), "dynamic_address_unregister", {
                "ip_addresses": ["192.0.2.1"], "tags": ["blocked"], "confirm": "yes",
            }, "firewall")

    def test_commit_polls_bounded_job_to_completion_without_reissuing_mutation(self):
        queued = response('<response status="success"><result><job>42</job></result></response>')
        active = response('<response status="success"><result><job><id>42</id><status>ACT</status><result>PEND</result><progress>10</progress></job></result></response>')
        done = response('<response status="success"><result><job><id>42</id><status>FIN</status><result>OK</result><progress>100</progress></job></result></response>')
        fake = FakeClient([queued, active, done])
        with mock.patch.object(client.time, "sleep") as sleep:
            data, changed, meta = client._commit(fake, "commit", {
                "confirm": "COMMIT", "wait": True, "poll_interval_seconds": 1, "max_polls": 2,
            }, "firewall")
        self.assertTrue(changed)
        self.assertEqual("OK", data["result"])
        self.assertEqual(2, data["polls"])
        self.assertEqual("firewall", meta["commit_scope"])
        self.assertEqual(1, sum(call[0] == "request" for call in fake.calls))
        self.assertEqual(2, sum(call[0] == "op" for call in fake.calls))
        sleep.assert_called_once_with(1)

    def test_commit_all_is_panorama_only_scoped_and_not_an_implicit_local_commit(self):
        queued = response('<response status="success"><result><job>9</job></result></response>')
        fake = FakeClient([queued])
        data, changed, meta = client._commit(fake, "commit_all", {
            "confirm": "COMMIT-ALL", "device_group": "branch",
            "managed_device_serials": ["0011223344"], "wait": False,
        }, "panorama")
        self.assertTrue(changed)
        self.assertEqual("9", data["job_id"])
        self.assertEqual("branch", meta["device_group"])
        request_params = fake.calls[0][2]
        self.assertEqual("all", request_params["action"])
        self.assertIn('<device-group><entry name="branch"><devices><entry name="0011223344"', request_params["cmd"])
        self.assertEqual(1, len(fake.calls))
        with self.assertRaisesRegex(client.PanosPackError, "only for Panorama"):
            client._commit(FakeClient(), "commit_all", {"confirm": "COMMIT-ALL"}, "firewall")

    def test_pending_and_system_commands_are_fixed_not_caller_supplied(self):
        for operation, expected in (("pending_changes", "<change-summary"), ("system_info", "<info")):
            fake = FakeClient([SUCCESS])
            client._read_action(fake, operation, {"command": "<delete><config /></delete>"})
            xml = client._element_xml(fake.calls[0][1])
            self.assertIn(expected, xml)
            self.assertNotIn("delete", xml)


class CredentialKeyAndEntryPointTests(unittest.TestCase):
    def test_fetch_key_accepts_json_and_hides_sdk_exceptions(self):
        parsed = types.SimpleNamespace(data=types.SimpleNamespace(value=json.dumps({
            "base_url": "https://pa.invalid", "target_type": "firewall", "api_key": "secret",
        })))
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(sync_detailed=mock.Mock(return_value=types.SimpleNamespace(status_code=200, parsed=parsed)))
        modules = {
            "attune": fake_attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual("firewall", client._fetch_key("pack.paloalto.credentials")["target_type"])
        fake_secrets.get_key.sync_detailed.assert_called_once_with(
            "pack.paloalto.credentials", client=fake_attune.context.client
        )
        fake_secrets.get_key.sync_detailed.side_effect = RuntimeError("secret")
        with mock.patch.dict(sys.modules, modules), self.assertRaises(client.PanosPackError) as caught:
            client._fetch_key("pack.paloalto.credentials")
        self.assertNotIn("secret", str(caught.exception))

    def test_entrypoint_rejects_non_object_and_redacts_unknown_errors(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("paloalto_action_test", ROOT / "actions" / "paloalto_action.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cases = [("[]", None), ('{"api_key":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO"))]
        for raw, error in cases:
            stdout, stderr = io.StringIO(), io.StringIO()
            execute = mock.patch.object(module, "execute_action", side_effect=error) if error else mock.patch.object(module, "execute_action")
            with execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "paloalto.system_info"}), mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
