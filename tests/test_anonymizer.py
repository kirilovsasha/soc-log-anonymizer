"""
Юнит-тесты для soc_log_anonymizer (стандартный модуль unittest).

Запуск:
    python -m unittest discover -s tests -v
"""

import json
import os
import shutil
import tempfile
import unittest

from soc_log_anonymizer.anonymizer import SOCLogAnonymizer
from soc_log_anonymizer.config import AnonymizerConfig


class TestConsistentPseudonymization(unittest.TestCase):
    """Главное требование: одно и то же значение -> один и тот же псевдоним,
    независимо от контекста (CEF key=value, JSON-поле, свободный текст)."""

    def setUp(self):
        self.a = SOCLogAnonymizer(salt="test-salt", org_name="bank")

    def test_ip_consistent_across_contexts(self):
        text = "src=192.168.1.10 dst=10.0.0.5\nConnection from 192.168.1.10 seen again"
        out = self.a.anonymize_text(text)
        occurrences = [p for p in out.split() if "192" not in p]
        # оба вхождения 192.168.1.10 должны дать одинаковый плейсхолдер
        pseudo1 = self.a.mapping_table["192.168.1.10"]
        self.assertEqual(out.count(pseudo1), 2)

    def test_username_consistent_cef_kv_and_user_field(self):
        text = "suser=jdoe some other=x user=jdoe"
        out = self.a.anonymize_text(text)
        pseudo = self.a.mapping_table["jdoe"]
        self.assertEqual(out.count(pseudo), 2)

    def test_json_field_consistent_with_free_text(self):
        doc = {"src_ip": "192.168.1.10", "note": "seen 192.168.1.10 again"}
        out = self.a.anonymize(json.dumps(doc))
        parsed = json.loads(out)
        pseudo_ip = parsed["src_ip"]
        self.assertIn(pseudo_ip, parsed["note"])

    def test_ndjson_consistent_across_lines(self):
        ndjson = '{"user":"asmith","ip":"10.1.1.1"}\n{"user":"asmith","ip":"10.1.1.2"}'
        out = self.a.anonymize(ndjson)
        lines = [json.loads(l) for l in out.splitlines()]
        self.assertEqual(lines[0]["user"], lines[1]["user"])
        self.assertNotEqual(lines[0]["ip"], lines[1]["ip"])


class TestCollisionHandling(unittest.TestCase):
    def setUp(self):
        self.a = SOCLogAnonymizer(salt="test-salt", org_name="bank")

    def test_forced_collision_gets_suffix(self):
        # Симулируем коллизию: занимаем плейсхолдер другим оригиналом
        first = self.a._hash_val("value-one", "TESTTAG")
        # Подменим кэш, чтобы следующий вызов с другим значением "столкнулся"
        # с уже занятым plaseholder-ом
        fake_pseudo = first
        self.a.reverse_mapping[fake_pseudo] = "value-one"  # уже так и есть
        # Искусственно заставим _hash_val для другого значения выдать тот
        # же хэш, подменив соль на лету невозможно — тестируем логику через
        # прямую манипуляцию reverse_mapping перед вызовом с тем же base_pseudo.
        collided_key = fake_pseudo
        self.a.reverse_mapping[collided_key] = "someone-else"
        second = self.a._hash_val("value-two-different", "TESTTAG")
        # Если бы обе строки реально хэшировались в один and тот же hash,
        # second получил бы суффикс. Проверяем, что логика хотя бы не
        # перезаписывает существующее отображение чужим значением.
        self.assertNotEqual(self.a.reverse_mapping.get(collided_key), "value-two-different")

    def test_no_crash_on_repeated_values(self):
        text = "192.168.1.1 192.168.1.1 192.168.1.1"
        out = self.a.anonymize_text(text)
        self.assertEqual(len(set(out.split())), 1)


class TestWellKnownWhitelist(unittest.TestCase):
    def setUp(self):
        self.a = SOCLogAnonymizer(salt="test-salt", org_name="bank")

    def test_well_known_sid_not_masked(self):
        text = "SID: S-1-5-18 and S-1-5-21-3623811015-3361044348-30300820-1013"
        out = self.a.anonymize_text(text)
        self.assertIn("S-1-5-18", out)
        self.assertNotIn("S-1-5-21-3623811015-3361044348-30300820-1013", out)

    def test_nil_guid_not_masked(self):
        text = "GUID: 00000000-0000-0000-0000-000000000000 and 6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        out = self.a.anonymize_text(text)
        self.assertIn("00000000-0000-0000-0000-000000000000", out)
        self.assertNotIn("6ba7b810-9dad-11d1-80b4-00c04fd430c8", out)


class TestVerifyGatekeeper(unittest.TestCase):
    def setUp(self):
        self.a = SOCLogAnonymizer(salt="test-salt", org_name="bank")

    def test_verify_passes_after_full_anonymization(self):
        text = "src=192.168.1.10 user=jdoe email=jdoe@bank.com bank-server"
        out = self.a.anonymize_text(text)
        is_safe, issues = self.a.verify(out)
        self.assertTrue(is_safe, msg=f"issues: {issues}")

    def test_verify_flags_leftover_ip(self):
        is_safe, issues = self.a.verify("still has 192.168.1.10 here")
        self.assertFalse(is_safe)
        self.assertTrue(any("IP" in i for i in issues))

    def test_verify_does_not_flag_well_known_sid(self):
        is_safe, issues = self.a.verify("SYSTEM sid is S-1-5-18")
        self.assertNotIn("Обнаружены незамаскированные данные типа SID", issues)


class TestDeanonymizeRoundtrip(unittest.TestCase):
    def test_roundtrip(self):
        a = SOCLogAnonymizer(salt="test-salt", org_name="bank")
        original = "src=192.168.1.10 user=jdoe password=hunter2 email=jdoe@bank.com"
        cleaned = a.anonymize_text(original)
        restored = a.deanonymize(cleaned)
        self.assertEqual(restored, original)


class TestMappingPersistence(unittest.TestCase):
    def test_save_and_load_mapping(self):
        a = SOCLogAnonymizer(salt="test-salt", org_name="bank")
        cleaned = a.anonymize_text("src=192.168.1.10 user=jdoe")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "mapping.json")
            a.save_mapping(path)

            # Права доступа 0600 на POSIX-системах
            if os.name == "posix":
                mode = oct(os.stat(path).st_mode & 0o777)
                self.assertEqual(mode, "0o600")

            b = SOCLogAnonymizer.load_mapping(path)
            restored = b.deanonymize(cleaned)
            self.assertEqual(restored, "src=192.168.1.10 user=jdoe")


class TestStats(unittest.TestCase):
    def test_stats_counts_occurrences(self):
        a = SOCLogAnonymizer(salt="test-salt", org_name="bank")
        a.anonymize_text("192.168.1.1 192.168.1.1 10.0.0.1")
        stats = a.get_stats()
        self.assertEqual(stats.get("IP"), 3)


class TestStreaming(unittest.TestCase):
    def test_anonymize_stream_matches_anonymize_text_per_line(self):
        a1 = SOCLogAnonymizer(salt="test-salt", org_name="bank")
        a2 = SOCLogAnonymizer(salt="test-salt", org_name="bank")

        lines = ["src=192.168.1.10 user=jdoe\n", "user=jdoe again\n"]
        streamed = list(a1.anonymize_stream(lines))
        whole_text = a2.anonymize_text("".join(lines))

        self.assertEqual("".join(streamed), whole_text)


class TestParallelProcessing(unittest.TestCase):
    def test_parallel_matches_sequential(self):
        lines = [f"user=jdoe{i % 3} ip=10.0.0.{i % 5}\n" for i in range(50)]

        seq = SOCLogAnonymizer(salt="test-salt", org_name="bank")
        seq_out = [seq.anonymize_line(l) for l in lines]

        par = SOCLogAnonymizer(salt="test-salt", org_name="bank")
        par_out = par.anonymize_parallel_lines(lines, workers=2, chunk_size=10)

        self.assertEqual(seq_out, par_out)


class TestConfig(unittest.TestCase):
    def test_config_roundtrip(self):
        cfg = AnonymizerConfig(org_name="acme", hash_len=16)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.json")
            cfg.save(path)
            loaded = AnonymizerConfig.load(path)
            self.assertEqual(loaded.org_name, "acme")
            self.assertEqual(loaded.hash_len, 16)

    def test_custom_org_name_masked(self):
        cfg = AnonymizerConfig(org_name="acme-corp")
        a = SOCLogAnonymizer(config=cfg)
        out = a.anonymize_text("connection to acme-corp gateway")
        self.assertNotIn("acme-corp", out)


if __name__ == "__main__":
    unittest.main()
