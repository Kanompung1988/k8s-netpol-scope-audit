import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit.py"
spec = importlib.util.spec_from_file_location("netpol", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class NetpolAuditTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.base = {"kind": "NetworkPolicy", "metadata": {"name": "demo", "namespace": "qa"},
                     "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"], "ingress": []}}

    def test_safe_fixture(self):
        self.assertEqual(audit.analyze(audit.load_documents(self.root / "examples/safe-policy.yaml"))["findings"], [])

    def test_review_fixture_rules(self):
        got = audit.analyze(audit.load_documents(self.root / "examples/review-policy.yaml"))
        self.assertEqual({f["rule"] for f in got["findings"]}, {"NP001", "NP003", "NP004", "NP005", "NP006", "NP007"})

    def test_absent_policytypes_is_inferred(self):
        self.base["spec"].pop("policyTypes")
        self.assertIn("NP002", {f["rule"] for f in audit.assess_policy(self.base)})

    def test_egress_default_inferred_when_rules_exist(self):
        self.base["spec"].pop("policyTypes")
        self.base["spec"]["egress"] = [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]
        self.assertIn("NP002", {f["rule"] for f in audit.assess_policy(self.base)})

    def test_empty_direction_is_default_deny(self):
        self.assertEqual({f["rule"] for f in audit.assess_policy(self.base)}, {"NP008"})

    def test_empty_peer_list_matches_all(self):
        self.base["spec"]["ingress"] = [{"from": [], "ports": [{"port": 443}]}]
        self.assertEqual({f["rule"] for f in audit.assess_policy(self.base)}, {"NP003"})

    def test_combined_namespace_pod_selector_is_intersection(self):
        self.base["spec"]["ingress"] = [{"from": [{"namespaceSelector": {"matchLabels": {"team": "a"}},
                                                      "podSelector": {"matchLabels": {"app": "b"}}}], "ports": [{"port": 443}]}]
        self.assertEqual(audit.assess_policy(self.base), [])

    def test_separate_ns_pod_is_union(self):
        self.base["spec"]["ingress"] = [{"from": [{"namespaceSelector": {"matchLabels": {"team": "a"}}},
                                                  {"podSelector": {"matchLabels": {"app": "b"}}}], "ports": [{"port": 443}]}]
        self.assertEqual({f["rule"] for f in audit.assess_policy(self.base)}, {"NP007"})

    def test_empty_namespace_selector_in_combined_peer_is_broad(self):
        self.base["spec"]["ingress"] = [{"from": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"app": "a"}}}], "ports": [{"port": 443}]}]
        self.assertEqual({f["rule"] for f in audit.assess_policy(self.base)}, {"NP004"})

    def test_broad_ipv6_cidr(self):
        self.assertTrue(audit.all_cidr("::/0"))

    def test_bounded_ipv4_cidr(self):
        self.assertFalse(audit.all_cidr("10.0.0.0/8"))

    def test_bad_cidr_not_assumed_broad(self):
        self.assertFalse(audit.all_cidr("bad"))

    def test_select_all_pods(self):
        self.base["spec"]["podSelector"] = {}
        self.assertIn("NP001", {f["rule"] for f in audit.assess_policy(self.base)})

    def test_malformed_policytypes_rejected(self):
        self.base["spec"]["policyTypes"] = ["Foo"]
        with self.assertRaises(ValueError):
            audit.assess_policy(self.base)

    def test_wrong_podselector_type(self):
        self.base["spec"]["podSelector"] = "all"
        with self.assertRaises(ValueError):
            audit.assess_policy(self.base)

    def test_missing_podselector_rejected(self):
        del self.base["spec"]["podSelector"]
        with self.assertRaises(ValueError):
            audit.assess_policy(self.base)

    def test_non_policy_documents_skipped(self):
        result = audit.analyze([{"kind": "ConfigMap", "metadata": {"name": "x"}}, self.base])
        self.assertEqual(result["skipped_non_networkpolicies"], 1)

    def test_list_resource_supported(self):
        result = audit.analyze([{"kind": "List", "items": [self.base]}])
        self.assertEqual(result["policy_count"], 1)

    def test_no_network_policy_is_error(self):
        with self.assertRaisesRegex(ValueError, "no NetworkPolicy"):
            audit.analyze([{"kind": "Pod"}])

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "a.yaml"
            src.write_text("kind: Pod")
            dst = Path(td) / "link"
            dst.symlink_to(src)
            with self.assertRaisesRegex(ValueError, "symlink"):
                audit.load_documents(dst)

    def test_size_cap(self):
        with patch.object(audit, "MAX_BYTES", 1):
            with self.assertRaises(ValueError):
                audit.load_documents(self.root / "examples/safe-policy.yaml")

    def test_bad_yaml_exit_one(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "broken.yaml"
            src.write_text("kind: [oops")
            self.assertEqual(audit.main([str(src)]), 1)

    def test_safe_cli(self):
        self.assertEqual(audit.main([str(self.root / "examples/safe-policy.yaml")]), 0)

    def test_risky_cli_fails(self):
        self.assertEqual(audit.main([str(self.root / "examples/review-policy.yaml")]), 2)

    def test_risky_cli_report_only(self):
        self.assertEqual(audit.main([str(self.root / "examples/review-policy.yaml"), "--fail-on", "none", "--format", "json"]), 0)

    def test_invalid_list(self):
        with self.assertRaises(ValueError):
            audit.collect_policies([{"kind": "List", "items": "bad"}])


if __name__ == "__main__":
    unittest.main()
