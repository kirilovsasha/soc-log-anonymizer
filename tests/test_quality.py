"""Quality filters, JSON formatting, result API, structured lines, corpus."""

import json
import os
import time
import unittest

from soc_log_anonymizer import AnonymizeResult, SOCLogAnonymizer
from soc_log_anonymizer.config import AnonymizerConfig
from soc_log_anonymizer.gui_logic import format_scan_report, mapping_rows_filtered
from soc_log_anonymizer.structured import join_continued_lines, parse_cef, parse_rfc5424_host


ROOT = os.path.dirname(os.path.dirname(__file__))
CORPUS = os.path.join(ROOT, "tests", "corpus", "golden.jsonl")


def _fast(**kwargs):
    cfg = AnonymizerConfig(pbkdf2_iterations=100, **kwargs)
    return SOCLogAnonymizer(salt="test-salt", org_name="bank", config=cfg)


class TestAllowlist(unittest.TestCase):
    def test_allowlist_keeps_public_dns(self):
        a = _fast(allowlist=["8.8.8.8"])
        out = a.anonymize_text("dns 8.8.8.8 and 1.1.1.1")
        self.assertIn("8.8.8.8", out)
        self.assertNotIn("1.1.1.1", out)


class TestHashFqdnPhoneUserFilters(unittest.TestCase):
    def test_hex_without_hash_context_stays(self):
        a = _fast()
        blob = "5f4dcc3b5aa765d61d8327deb882cf99"
        out = a.anonymize_text(f"correlation {blob} done")
        self.assertIn(blob, out)
        safe, issues = a.verify(out)
        self.assertTrue(safe, issues)

    def test_hex_with_hash_context_masked(self):
        a = _fast()
        blob = "5f4dcc3b5aa765d61d8327deb882cf99"
        out = a.anonymize_text(f"md5={blob}")
        self.assertNotIn(blob, out)

    def test_fqdn_stopword(self):
        a = _fast()
        self.assertIn("for.local", a.anonymize_text("wait for.local now"))

    def test_windows_path_segment_not_user(self):
        a = _fast()
        line = r"copy Windows\System32\cmd.exe"
        self.assertEqual(a.anonymize_text(line), line)


class TestJsonFormattingAndResult(unittest.TestCase):
    def test_compact_json_stays_single_line(self):
        a = _fast()
        raw = '{"user":"alice","ok":true,"n":1}'
        out = a.anonymize(raw)
        self.assertNotIn("\n", out)
        parsed = json.loads(out)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["n"], 1)
        self.assertNotEqual(parsed["user"], "alice")

    def test_pretty_json_keeps_newlines(self):
        a = _fast()
        raw = '{\n  "user": "alice"\n}'
        out = a.anonymize(raw)
        self.assertIn("\n", out)

    def test_anonymize_result_object(self):
        a = _fast()
        result = a.anonymize_result("user=jdoe from 10.0.0.5")
        self.assertIsInstance(result, AnonymizeResult)
        self.assertNotIn("jdoe", result.text)
        self.assertTrue(result.stats)
        self.assertTrue(result.mapping)


class TestStructuredAndMultiline(unittest.TestCase):
    def test_join_backslash_continuation(self):
        text = "hello \\\n world\n"
        self.assertIn("hello world", join_continued_lines(text))

    def test_rfc5424_host_split(self):
        line = "<34>1 2026-09-16T10:22:01Z vpn.example.com sshd - - - x"
        parts = parse_rfc5424_host(line)
        self.assertIsNotNone(parts)
        self.assertEqual(parts[1], "vpn.example.com")

    def test_cef_header_parse(self):
        line = "CEF:0|Vendor|Product|1.0|100|Name|10|src=10.0.0.5 suser=jdoe"
        parsed = parse_cef(line)
        self.assertIsNotNone(parsed)
        self.assertIn("src=10.0.0.5", parsed[2])

    def test_rfc5424_host_masked(self):
        a = _fast()
        line = "<34>1 2026-09-16T10:22:01Z vpn.bank.local sshd - - - ok"
        out = a.anonymize_text(line)
        self.assertNotIn("vpn.bank.local", out)
        self.assertIn("sshd", out)


class TestGoldenCorpus(unittest.TestCase):
    def test_corpus_invariants(self):
        a = _fast()
        with open(CORPUS, encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        self.assertGreaterEqual(len(rows), 20)
        failures = []
        for row in rows:
            out = a.anonymize(row["input"])
            for token in row.get("must_keep") or []:
                if token not in out:
                    failures.append(f"{row['id']}: missing {token!r} in {out!r}")
            for token in row.get("must_not_contain") or []:
                if token in out:
                    failures.append(f"{row['id']}: still contains {token!r} in {out!r}")
        self.assertFalse(failures, "\n".join(failures))


class TestScanHelpers(unittest.TestCase):
    def test_scan_report_empty(self):
        self.assertIn("не найдено", format_scan_report([]))

    def test_mapping_filter_by_type(self):
        rows = mapping_rows_filtered(
            {"10.0.0.1": "[IP_aa]", "bob": "[USER_bb]"},
            "", "IP", lambda p: "IP" if p.startswith("[IP_") else "USER",
        )
        self.assertEqual(rows, [("10.0.0.1", "[IP_aa]")])


class TestBenchmarkSmoke(unittest.TestCase):
    def test_five_thousand_lines_under_budget(self):
        a = _fast()
        line = "sshd: Accepted password for alice from 10.0.0.5 port 22\n"
        payload = line * 5000
        started = time.perf_counter()
        out = a.anonymize_text(payload)
        elapsed = time.perf_counter() - started
        self.assertNotIn("10.0.0.5", out)
        self.assertLess(elapsed, 20.0, f"too slow: {elapsed:.2f}s")


if __name__ == "__main__":
    unittest.main()
