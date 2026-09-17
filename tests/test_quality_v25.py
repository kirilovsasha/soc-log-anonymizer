"""Belarus PII, residual verify, quoted KV, AUTH expansions, mask strategies."""

from __future__ import annotations

import unittest

from soc_log_anonymizer import SOCLogAnonymizer
from soc_log_anonymizer.config import AnonymizerConfig
from soc_log_anonymizer.pii import (
    is_plausible_iban_by,
    is_plausible_pan,
    is_valid_unp,
    residual_risk_score,
    residual_scan,
)


def _fast(**kwargs):
    cfg = AnonymizerConfig(pbkdf2_iterations=100, **kwargs)
    return SOCLogAnonymizer(salt="test-salt", org_name="bank", config=cfg)


class TestBelarusPiiValidators(unittest.TestCase):
    def test_unp_checksum(self):
        self.assertTrue(is_valid_unp("200988541"))
        self.assertTrue(is_valid_unp("100000007"))
        self.assertFalse(is_valid_unp("200988542"))
        self.assertFalse(is_valid_unp("12345"))

    def test_pan_luhn(self):
        self.assertTrue(is_plausible_pan("4111111111111111"))
        self.assertTrue(is_plausible_pan("4111 1111 1111 1111"))
        self.assertFalse(is_plausible_pan("4111111111111112"))
        self.assertFalse(is_plausible_pan("0000000000000000"))

    def test_iban_by(self):
        self.assertTrue(is_plausible_iban_by("BY13AKBB36120000000000000000"))
        self.assertFalse(is_plausible_iban_by("BY00AKBB36120000000000000000"))


class TestBelarusPiiMasking(unittest.TestCase):
    def test_unp_masked(self):
        a = _fast()
        out = a.anonymize_text("payer UNP 200988541 registered")
        self.assertNotIn("200988541", out)
        self.assertIn("[UNP_", out)

    def test_pan_partial_keeps_last4(self):
        a = _fast()
        out = a.anonymize_text("card 4111111111111111 charged")
        self.assertNotIn("4111111111111111", out)
        self.assertTrue(out.rstrip().endswith("1111") or "1111" in out)
        self.assertIn("[PAN_", out)

    def test_iban_partial_keeps_country(self):
        a = _fast()
        iban = "BY13AKBB36120000000000000000"
        out = a.anonymize_text(f"pay to {iban} now")
        self.assertNotIn(iban, out)
        self.assertIn("BY13", out)
        self.assertIn("[IBAN_", out)

    def test_by_personal_id(self):
        a = _fast()
        pid = "3011089A001PB1"
        out = a.anonymize_text(f"id {pid} checked")
        self.assertNotIn(pid, out)
        self.assertIn("[BY_ID_", out)

    def test_by_phone_and_fqdn(self):
        a = _fast()
        out = a.anonymize_text("call +375291234567 host vpn.bank.by")
        self.assertNotIn("+375291234567", out)
        self.assertNotIn("vpn.bank.by", out)
        self.assertIn("+3", out)  # partial keeps a short head
        self.assertIn("[PHONE_", out)
        self.assertIn("[FQDN_", out)

    def test_json_unp_key(self):
        a = _fast()
        out = a.anonymize('{"unp":"200988541","ok":true}')
        self.assertNotIn("200988541", out)
        self.assertIn('"ok"', out)


class TestQuotedKeyValue(unittest.TestCase):
    def test_quoted_user_with_spaces(self):
        a = _fast()
        out = a.anonymize_text('login user="Alice Smith" ok')
        self.assertNotIn("Alice Smith", out)
        self.assertIn('user="', out)

    def test_quoted_password(self):
        a = _fast()
        out = a.anonymize_text("password='s3cret value!' next=1")
        self.assertNotIn("s3cret value!", out)
        self.assertIn("password=", out)


class TestAuthExpansions(unittest.TestCase):
    def test_invalid_user(self):
        a = _fast()
        out = a.anonymize_text("sshd: Invalid user bob from 10.0.0.5")
        self.assertNotIn(" bob ", out)
        self.assertNotIn("10.0.0.5", out)

    def test_sudo_line(self):
        a = _fast()
        out = a.anonymize_text("sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root")
        self.assertNotIn("alice", out)
        self.assertIn("TTY=pts/0", out)

    def test_windows_account_name(self):
        a = _fast()
        out = a.anonymize_text("Account Name:\tjdoe")
        self.assertNotIn("jdoe", out)
        self.assertIn("Account Name:", out)

    def test_auth_failure_phrase(self):
        a = _fast()
        out = a.anonymize_text("authentication failure for user bob from host")
        self.assertNotIn("bob", out)


class TestResidualVerify(unittest.TestCase):
    def test_residual_finds_raw_email(self):
        findings = residual_scan("still visible jdoe@bank.by here")
        kinds = {k for k, _ in findings}
        self.assertIn("EMAIL", kinds)

    def test_verify_flags_residual_when_patterns_skipped(self):
        # Force residual-only path: disable built-in email by using text that
        # residual catches after a no-op anonymize of empty-ish content.
        a = _fast()
        # Inject leftover by verifying a non-anonymized blob directly.
        safe, issues = a.verify("contact leak@example.com please")
        self.assertFalse(safe)
        self.assertTrue(any("EMAIL" in i or "Residual" in i for i in issues))

    def test_quality_report_includes_residual_risk(self):
        a = _fast()
        report = a.get_quality_report("mail leak@example.com")
        self.assertIn("residual_risk", report)
        self.assertGreaterEqual(report["residual_risk"], 0)

    def test_residual_risk_score_empty(self):
        self.assertEqual(residual_risk_score([]), 0)

    def test_anonymized_text_is_safe(self):
        a = _fast()
        cleaned = a.anonymize_text("user alice mail alice@bank.by ip 10.1.1.1")
        safe, issues = a.verify(cleaned)
        self.assertTrue(safe, issues)


class TestMaskStrategies(unittest.TestCase):
    def test_full_phone_when_configured(self):
        a = _fast(mask_strategies={"PHONE": "full"})
        out = a.anonymize_text("call +375291234567")
        self.assertNotIn("+375", out)
        self.assertIn("[PHONE_", out)

    def test_format_strategy(self):
        a = _fast(mask_strategies={"BY_ID": "format"})
        out = a.anonymize_text("id 3011089A001PB1")
        self.assertIn("9999999X999XX9", out)


if __name__ == "__main__":
    unittest.main()
