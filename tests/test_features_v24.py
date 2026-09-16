"""Corpus FP/FN scoring and new feature coverage tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from soc_log_anonymizer import SOCLogAnonymizer
from soc_log_anonymizer.config import AnonymizerConfig
from soc_log_anonymizer.json_stream import iter_json_or_text_chunks
from soc_log_anonymizer.mapping_crypto import (
    decrypt_with_passphrase,
    encrypt_with_passphrase,
    unwrap_payload,
    wrap_payload,
)
from soc_log_anonymizer.parallel_merge import (
    apply_pseudo_rewrite,
    build_pseudo_rewrite,
    merge_mappings_deterministic,
)

ROOT = os.path.dirname(os.path.dirname(__file__))
CORPUS = os.path.join(ROOT, "tests", "corpus", "golden.jsonl")


def _fast(**kwargs):
    cfg = AnonymizerConfig(pbkdf2_iterations=100, **kwargs)
    return SOCLogAnonymizer(salt="test-salt", org_name="bank", config=cfg)


def score_corpus(anonymizer: SOCLogAnonymizer, rows):
    """Return (true_positives, false_negatives, false_positives, total_checks).

    * must_not_contain tokens that are gone → TP (sensitive removed)
    * must_not_contain tokens still present → FN
    * must_keep tokens missing → FP (over-masking / corruption)
    """
    tp = fn = fp = 0
    checks = 0
    for row in rows:
        out = anonymizer.anonymize(row["input"])
        for token in row.get("must_not_contain") or []:
            checks += 1
            if token in out:
                fn += 1
            else:
                tp += 1
        for token in row.get("must_keep") or []:
            checks += 1
            if token not in out:
                fp += 1
    return tp, fn, fp, checks


class TestCorpusMetrics(unittest.TestCase):
    def test_fp_fn_rates(self):
        a = _fast()
        with open(CORPUS, encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        self.assertGreaterEqual(len(rows), 30)
        tp, fn, fp, checks = score_corpus(a, rows)
        self.assertGreater(checks, 0)
        # Perfect score expected on curated golden corpus.
        self.assertEqual(fn, 0, f"false negatives={fn} tp={tp} checks={checks}")
        self.assertEqual(fp, 0, f"false positives={fp} tp={tp} checks={checks}")
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        precision_proxy = tp / (tp + fp) if (tp + fp) else 1.0
        self.assertGreaterEqual(recall, 0.99)
        self.assertGreaterEqual(precision_proxy, 0.99)


class TestVendorPatterns(unittest.TestCase):
    def test_su_initiator_and_target(self):
        a = _fast()
        line = "su: 'su root' failed for lonvick on /dev/pts/8"
        out = a.anonymize_text(line)
        self.assertNotIn("root", out)
        self.assertNotIn("lonvick", out)
        self.assertIn("/dev/pts/8", out)

    def test_palo_alto_from_user(self):
        a = _fast()
        out = a.anonymize_text("THREAT from user alice failed authentication")
        self.assertNotIn("alice", out)
        self.assertIn("from user ", out)
        self.assertIn("failed authentication", out)

    def test_fortinet_usr_field(self):
        a = _fast()
        out = a.anonymize_text("usr=jdoe srcip=10.0.0.8 action=login")
        self.assertNotIn("jdoe", out)
        self.assertNotIn("10.0.0.8", out)


class TestJsonStream(unittest.TestCase):
    def test_pretty_json_across_lines(self):
        a = _fast()
        lines = ['{\n', '  "user": "alice",\n', '  "ip": "10.0.0.5"\n', '}\n']
        out = "".join(a.anonymize_stream(lines))
        self.assertNotIn("alice", out)
        self.assertNotIn("10.0.0.5", out)
        self.assertIn("\n", out)

    def test_chunker_mixed(self):
        text_lines = ["hello\n", '{\n', '  "a": 1\n', '}\n', "bye\n"]
        kinds = [k for k, _ in iter_json_or_text_chunks(iter(text_lines))]
        self.assertIn("json", kinds)
        self.assertIn("text", kinds)


class TestParallelMerge(unittest.TestCase):
    def test_collision_suffixes_stable(self):
        # Simulate two workers assigning opposite suffixes for same hash body.
        m1 = {"alpha": "[USER_deadbeef]", "beta": "[USER_deadbeef_2]"}
        m2 = {"beta": "[USER_deadbeef]", "alpha": "[USER_deadbeef_2]"}
        canonical, reverse = merge_mappings_deterministic([m1, m2])
        self.assertEqual(canonical["alpha"], "[USER_deadbeef]")
        self.assertEqual(canonical["beta"], "[USER_deadbeef_2]")
        self.assertEqual(reverse["[USER_deadbeef]"], "alpha")
        rewrite = build_pseudo_rewrite([m1, m2], canonical)
        # Worker m2 labelled alpha as _2; canonical assigns alpha the base form.
        self.assertEqual(rewrite.get("[USER_deadbeef_2]"), "[USER_deadbeef]")
        self.assertEqual(apply_pseudo_rewrite("x [USER_deadbeef_2] y", {"[USER_deadbeef_2]": "[USER_deadbeef]"}), "x [USER_deadbeef] y")


class TestMappingCrypto(unittest.TestCase):
    def test_passphrase_roundtrip(self):
        payload = {"schema_version": 1, "salt": "s", "mapping": {"a": "[IP_1]"}}
        raw = json.dumps(payload).encode("utf-8")
        env = encrypt_with_passphrase(raw, "secret-pass", iterations=100)
        restored = json.loads(decrypt_with_passphrase(env, "secret-pass").decode("utf-8"))
        self.assertEqual(restored["mapping"], payload["mapping"])

        wrapped = wrap_payload(payload, passphrase="secret-pass", iterations=100)
        self.assertEqual(wrapped.get("encryption"), "passphrase-hmac-sha256")
        unwrapped = unwrap_payload(wrapped, passphrase="secret-pass")
        self.assertEqual(unwrapped["salt"], "s")

    def test_save_load_encrypted_mapping(self):
        a = _fast()
        a.anonymize_text("user=jdoe from 10.0.0.5")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "m.json")
            a.save_mapping(path, passphrase="unit-test-pass", kdf_iterations=100)
            with open(path, encoding="utf-8") as handle:
                disk = json.load(handle)
            self.assertIn("encryption", disk)
            b = SOCLogAnonymizer.load_mapping(path, passphrase="unit-test-pass")
            self.assertEqual(b.mapping_table, a.mapping_table)


if __name__ == "__main__":
    unittest.main()
