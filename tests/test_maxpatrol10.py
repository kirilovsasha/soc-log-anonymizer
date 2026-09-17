"""MaxPatrol 10 / PT SIEM field coverage tests."""

from __future__ import annotations

import json
import unittest

from soc_log_anonymizer import SOCLogAnonymizer
from soc_log_anonymizer.config import AnonymizerConfig, _MAXPATROL10_JSON_KEYS


def _fast(**kwargs):
    cfg = AnonymizerConfig(pbkdf2_iterations=100, **kwargs)
    return SOCLogAnonymizer(salt="mp10-salt", org_name="bank", config=cfg)


class TestMaxPatrol10Fields(unittest.TestCase):
    def test_preset_non_empty(self):
        self.assertGreaterEqual(len(_MAXPATROL10_JSON_KEYS), 20)
        keys = AnonymizerConfig().normalize_keys().sensitive_json_keys
        # Flattened forms present after normalize_keys()
        self.assertIn("eventsrchost", keys)
        self.assertIn("subjectaccountname", keys)
        self.assertIn("recvipv4", keys)

    def test_flat_dotted_export_api_style(self):
        """MP API/export often uses dotted strings as *literal* JSON keys."""
        a = _fast()
        doc = {
            "time": "2021-03-16T16:01:05.0000000Z",
            "event_src.host": "vpn.bank.by",
            "event_src.ip": "10.0.0.8",
            "subject.account.name": "jdoe",
            "subject.account.domain": "CORP",
            "src.ip": "10.0.0.5",
            "dst.host": "dc01.bank.local",
            "recv_ipv4": "10.1.1.9",
            "id": "PT_Microsoft_Windows_eventlog_4624",
            "text": "login ok",
        }
        out = json.loads(a.anonymize(json.dumps(doc)))
        self.assertNotIn("vpn.bank.by", json.dumps(out))
        self.assertNotIn("jdoe", json.dumps(out))
        self.assertNotIn("10.0.0.5", json.dumps(out))
        self.assertNotIn("10.0.0.8", json.dumps(out))
        self.assertNotIn("10.1.1.9", json.dumps(out))
        self.assertTrue(out["event_src.host"].startswith("[FQDN_"))
        self.assertTrue(out["subject.account.name"].startswith("[USER_"))
        self.assertTrue(out["src.ip"].startswith("[IP_"))
        self.assertTrue(out["recv_ipv4"].startswith("[IP_"))
        # Non-sensitive taxonomy kept
        self.assertEqual(out["id"], "PT_Microsoft_Windows_eventlog_4624")
        self.assertIn("login", out["text"])

    def test_nested_taxonomy_extended(self):
        a = _fast()
        doc = {
            "subject": {
                "account": {
                    "name": "alice",
                    "id": "S-1-5-21-1-2-3-1001",
                    "domain": "BANK",
                    "session_id": "0x1234",
                },
                "email": "alice@bank.by",
            },
            "object": {"account": {"name": "svc_sql", "id": "svc_sql$"}},
            "src": {"ip": "10.0.0.5", "mac": "00:1A:2B:3C:4D:5E", "host": "ws01.bank.by"},
            "dst": {"ip": "10.0.0.1", "fqdn": "db.bank.local"},
            "event_src": {"host": "mp10-collector.bank.by", "ip": "10.9.9.9"},
            "asset": {"name": "dc01.bank.local", "ip": "10.0.0.10"},
            "action": "login",
            "status": "success",
        }
        out = json.loads(a.anonymize(json.dumps(doc)))
        self.assertTrue(out["subject"]["account"]["name"].startswith("[USER_"))
        self.assertTrue(out["subject"]["account"]["id"].startswith("["))
        self.assertTrue(out["subject"]["email"].startswith("[EMAIL_"))
        self.assertTrue(out["src"]["mac"].startswith("[MAC_"))
        self.assertTrue(out["event_src"]["host"].startswith("[FQDN_"))
        self.assertTrue(out["asset"]["ip"].startswith("[IP_"))
        self.assertEqual(out["action"], "login")
        self.assertEqual(out["status"], "success")

    def test_flat_and_nested_same_pseudonym(self):
        a = _fast()
        nested = json.loads(a.anonymize(json.dumps({
            "event_src": {"host": "siem.bank.by"},
        })))
        flat = json.loads(a.anonymize(json.dumps({
            "event_src.host": "siem.bank.by",
        })))
        self.assertEqual(nested["event_src"]["host"], flat["event_src.host"])


if __name__ == "__main__":
    unittest.main()
