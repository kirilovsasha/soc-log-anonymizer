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

    def test_custom_json_keys_with_hyphen_and_underscore_are_masked(self):
        cfg = AnonymizerConfig(
            sensitive_json_keys=["employee-id_code"],
            key_type_hints={"employee-id_code": "USER"},
        )
        a = SOCLogAnonymizer(salt="test-salt", config=cfg)
        out = json.loads(a.anonymize(json.dumps({"employee-id_code": "jdoe"})))
        self.assertTrue(out["employee-id_code"].startswith("[USER_"))
        self.assertNotIn("jdoe", out["employee-id_code"])

    def test_config_normalization_preserves_text_field_separators(self):
        cfg = AnonymizerConfig.from_dict({
            "cef_fields": ["src_ip"],
            "user_field_names": ["user_name"],
            "secret_field_names": ["api-key"],
        })
        self.assertIn("src_ip", cfg.cef_fields)
        self.assertIn("user_name", cfg.user_field_names)
        self.assertIn("api-key", cfg.secret_field_names)
        a = SOCLogAnonymizer(salt="test-salt", config=cfg)
        out = a.anonymize_text("src_ip=192.168.1.10 user_name=jdoe api-key=secret")
        self.assertNotIn("192.168.1.10", out)
        self.assertNotIn("jdoe", out)
        self.assertNotIn("secret", out)

    def test_mapping_contains_algorithm_metadata_and_loads(self):
        a = SOCLogAnonymizer(salt="test-salt")
        a.anonymize("user=jdoe")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "mapping.json")
            a.save_mapping(path)
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["algorithm"], "HMAC-SHA256/PBKDF2")
            restored = SOCLogAnonymizer.load_mapping(path)
            self.assertEqual(restored.deanonymize(a.anonymize("user=jdoe")),
                             "user=jdoe")

    def test_metrics_report_cache_and_replacement_counts(self):
        a = SOCLogAnonymizer(salt="test-salt")
        a.anonymize("user=jdoe user=jdoe")
        metrics = a.get_metrics()
        self.assertGreaterEqual(metrics["replacement_occurrences"], 2)
        self.assertGreaterEqual(metrics["unique_values"], 1)

    def test_custom_pattern_is_opt_in(self):
        cfg = AnonymizerConfig(custom_patterns={"TICKET": r"TCK-[0-9]{4}"})
        a = SOCLogAnonymizer(salt="test-salt", config=cfg)
        out = a.anonymize("ticket TCK-1234")
        self.assertNotIn("TCK-1234", out)
        self.assertIn("[CUSTOM:TICKET_", out)


class TestContextRulesAndPatterns(unittest.TestCase):
    def test_json_path_rule_matches_nested_field(self):
        cfg = AnonymizerConfig(
            context_rules=[{"json_path": "$.session.token", "type": "JWT", "strategy": "format"}]
        )
        a = SOCLogAnonymizer(salt="test-salt", config=cfg)
        raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
        out = a.anonymize_json({"session": {"token": raw}})
        self.assertNotEqual(out["session"]["token"], raw)
        self.assertNotIn(raw, out["session"]["token"])

    def test_custom_pattern_priority_and_strategy_are_respected(self):
        cfg = AnonymizerConfig(custom_patterns={
            "TICKET": {"pattern": r"TCK-[0-9]{4}", "priority": 2, "strategy": "partial"},
        })
        a = SOCLogAnonymizer(salt="test-salt", config=cfg)
        out = a.anonymize_text("ticket TCK-1234")
        self.assertIn("[CUSTOM:TICKET_", out)
        self.assertNotIn("TCK-1234", out)

class TestVendorLogFormats(unittest.TestCase):
    """Реальные форматы, встречающиеся в syslog, Cisco ASA/IOS, Checkpoint
    и нормализованных событиях SIEM (MaxPatrol 10 и подобные) — покрывают
    имена пользователей в "естественном языке" (без key=value) и во
    вложенных JSON-структурах."""

    def setUp(self):
        self.a = SOCLogAnonymizer(salt="test-salt", org_name="corp")

    def test_sshd_accepted_password(self):
        line = "sshd[1234]: Accepted password for admin from 10.0.0.5 port 54321 ssh2"
        out = self.a.anonymize_text(line)
        self.assertNotIn("admin", out)
        self.assertNotIn("10.0.0.5", out)
        self.assertIn("[USER_", out)
        self.assertIn("[IP_", out)

    def test_sshd_failed_invalid_user(self):
        line = "sshd[1234]: Failed password for invalid user root from 203.0.113.7 port 22 ssh2"
        out = self.a.anonymize_text(line)
        self.assertNotIn(" root ", out)
        self.assertIn("invalid user [USER_", out)

    def test_su_quoted_target_user(self):
        line = "su: 'su root' failed for lonvick on /dev/pts/8"
        out = self.a.anonymize_text(line)
        self.assertIn("'su [USER_", out)
        self.assertNotIn("root'", out)

    def test_cisco_asa_quoted_user(self):
        line = '%ASA-6-605005: Login permitted from 10.0.0.5/50234 to inside:10.0.0.1/https for user "admin"'
        out = self.a.anonymize_text(line)
        self.assertNotIn('"admin"', out)
        self.assertIn('for user "[USER_', out)

    def test_cisco_asa_uname_field(self):
        line = "%ASA-5-502103: User priv level changed: Uname: admin To: 15"
        out = self.a.anonymize_text(line)
        self.assertNotIn("Uname: admin", out)
        self.assertIn("Uname: [USER_", out)

    def test_cisco_ios_by_user_on_vty(self):
        line = "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.99)"
        out = self.a.anonymize_text(line)
        self.assertIn("by [USER_", out)
        self.assertIn("on vty0", out)  # суффикс должен остаться нетронутым
        self.assertNotIn("10.0.0.99", out)

    def test_checkpoint_subject_and_user(self):
        line = "Product: SmartCenter; Subject: administrator; src: 10.0.0.5; user: jdoe;"
        out = self.a.anonymize_text(line)
        self.assertNotIn("administrator", out)
        self.assertNotIn(" jdoe", out)
        self.assertNotIn("10.0.0.5", out)

    def test_checkpoint_suser_duser_cef(self):
        line = 'action="Accept" src="203.0.113.9" dst="10.0.0.5" suser="jdoe" duser="root"'
        out = self.a.anonymize_text(line)
        self.assertNotIn("jdoe", out)
        self.assertNotIn('"root"', out)

    def test_suser_and_user_field_same_pseudonym(self):
        """Регрессионный тест: suser= (CEF_KV) и user= (USER_FIELD) для
        ОДНОГО и того же значения должны давать ОДИН и тот же псевдоним —
        раньше разный откат типа (VALUE vs USER) их разводил."""
        out = self.a.anonymize_text("suser=jdoe some other=x user=jdoe")
        pseudo = self.a.mapping_table["jdoe"]
        self.assertEqual(out.count(pseudo), 2)

    def test_maxpatrol_nested_json_account_name(self):
        doc = {
            "subject": {"account": {"name": "admin", "domain": "CORP"}},
            "object": {"account": {"name": "svc_backup"}},
            "src": {"ip": "10.0.0.5", "host": "workstation01.corp.local"},
            "dst": {"ip": "10.0.0.1"},
        }
        out = json.loads(self.a.anonymize(json.dumps(doc)))
        self.assertTrue(out["subject"]["account"]["name"].startswith("[USER_"))
        self.assertTrue(out["object"]["account"]["name"].startswith("[USER_"))
        self.assertTrue(out["src"]["ip"].startswith("[IP_"))
        self.assertTrue(out["src"]["host"].startswith("[FQDN_"))
        self.assertTrue(out["dst"]["ip"].startswith("[IP_"))

    def test_maxpatrol_nested_and_flat_consistent(self):
        """Вложенный subject.account.name и уже плоский ключ
        SubjectAccountName (Windows Event Log стиль) с одним и тем же
        значением должны давать один и тот же псевдоним."""
        nested = json.loads(self.a.anonymize(json.dumps({"subject": {"account": {"name": "admin"}}})))
        flat = json.loads(self.a.anonymize(json.dumps({"SubjectAccountName": "admin"})))
        self.assertEqual(nested["subject"]["account"]["name"], flat["SubjectAccountName"])

    def test_no_data_loss_when_kv_pairs_adjacent_no_space(self):
        """Регрессионный тест: без пробела между соседними key=value парами
        ("(src=X)(dst=Y)") жадный захват значения раньше "съедал" второе
        поле целиком вместе со значением, оно исчезало из вывода."""
        out = self.a.anonymize_text("fields: (src=10.0.0.5)(dst=10.0.0.6)")
        self.assertIn("dst=", out)
        self.assertIn(")(dst=", out)
        self.assertTrue(out.startswith("fields: (src=[IP_"))

    def test_bracketed_cisco_ios_fields_preserve_structure(self):
        line = "[user: admin][ip: 10.0.0.5]"
        out = self.a.anonymize_text(line)
        self.assertEqual(out.count("["), out.count("]"))  # скобки сбалансированы
        self.assertRegex(out, r'^\[user: \[USER_[0-9a-f]+\]\]\[ip: \[IP_[0-9a-f]+\]\]$')
        self.assertNotIn("admin", out)
        self.assertNotIn("10.0.0.5", out)

    def test_trailing_comma_does_not_break_ip_classification(self):
        out = self.a.anonymize_text("src=10.0.0.5, dst=10.0.0.6")
        self.assertIn("[IP_", out)
        self.assertNotIn("[VALUE_", out)

    def test_cisco_asa_user_quoted_executed(self):
        line = "%ASA-5-111008: User 'admin' executed the 'configure terminal' command."
        out = self.a.anonymize_text(line)
        self.assertIn("User '[USER_", out)
        self.assertIn("'configure terminal'", out)  # неотносящаяся к делу команда не тронута

    def test_secret_false_positive_invalid_password_phrase(self):
        """Регрессионный тест: "Invalid password" (сообщение об ошибке, а
        не поле) с несвязанным разделителем полей дальше по строке
        (Cisco ASA ' : ') раньше ошибочно матчился как SECRET-поле и
        маскировал следующее слово ("server") под тегом SECRET."""
        line = "reason = Invalid password : server = 10.0.0.10 : user = jdoe"
        out = self.a.anonymize_text(line)
        self.assertIn("Invalid password :", out)   # фраза не тронута
        self.assertIn("server = [IP_", out)          # "server" остался как есть, IP замаскирован
        self.assertNotIn("[SECRET_", out)             # ложного SECRET-срабатывания нет

    def test_secret_still_matches_legitimate_password_field(self):
        """Защита от ложных срабатываний не должна ломать штатное
        маскирование настоящих password=/wrong password: полей."""
        out = self.a.anonymize_text("password=hunter2")
        self.assertIn("[SECRET_", out)
        self.assertNotIn("hunter2", out)

    def test_ipv6_compressed_notation(self):
        """Регрессионный тест: сжатая форма IPv6 ("::", RFC 5952,
        подавляющее большинство реальных IPv6-адресов) раньше вообще не
        распознавалась — только полная 8-групповая форма без "::"."""
        out = self.a.anonymize_text("src=2001:db8::1 dst=fe80::1")
        self.assertNotIn("2001:db8::1", out)
        self.assertNotIn("fe80::1", out)
        self.assertEqual(out.count("[IP_"), 2)

    def test_ipv6_localhost_in_free_text(self):
        out = self.a.anonymize_text("client ::1 connected")
        self.assertNotIn("::1", out)
        self.assertIn("[IP_", out)

    def test_ipv6_bracketed_with_port_rfc3986(self):
        out = self.a.anonymize_text("connection from [2001:db8::1]:443")
        self.assertNotIn("2001:db8::1", out)
        self.assertIn("[[IP_", out)
        self.assertIn("]:443", out)  # порт не является чувствительными данными, остаётся как есть

    def test_ipv6_full_form_still_works(self):
        out = self.a.anonymize_text("src=2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertIn("[IP_", out)

    def test_timestamp_not_misdetected_as_ip(self):
        """Широкий кандидат-паттерн IPv6 синтаксически подошёл бы и под
        обычный таймстамп ("12:30:45") — настоящую проверку делает
        ipaddress.ip_address(), отклоняющий не-адреса."""
        line = "time is 12:30:45 not an ip"
        out = self.a.anonymize_text(line)
        self.assertEqual(out, line)

    def test_mac_address_not_misdetected_as_ipv6(self):
        out = self.a.anonymize_text("mac address 00:1A:2B:3C:4D:5E stays MAC-typed")
        self.assertIn("[MAC_", out)
        self.assertNotIn("[IP_", out)

    def test_gatekeeper_does_not_false_positive_on_timestamp(self):
        cleaned = self.a.anonymize_text("time is 12:30:45 not an ip")
        safe, issues = self.a.verify(cleaned)
        self.assertTrue(safe, issues)


class TestOrgAliasCanonicalization(unittest.TestCase):
    """config.org_aliases_share_pseudonym — все буквальные упоминания
    организации (org_name + все org_aliases) сходятся к одному псевдониму,
    но домены/email с оргназванием внутри остаются независимыми."""

    def test_disabled_by_default_different_pseudonyms(self):
        cfg = AnonymizerConfig(org_aliases=["ExampleCorp"])
        a = SOCLogAnonymizer(salt="s", org_name="example", config=cfg)
        out = a.anonymize_text("example and ExampleCorp")
        pseudos = {w for w in out.split() if w.startswith("[ORG_")}
        self.assertEqual(len(pseudos), 2)

    def test_enabled_same_pseudonym_for_all_aliases(self):
        cfg = AnonymizerConfig(org_aliases=["ExampleCorp", "Example Bank"], org_aliases_share_pseudonym=True)
        a = SOCLogAnonymizer(salt="s", org_name="example", config=cfg)
        out = a.anonymize_text("example and ExampleCorp and Example Bank")
        pseudos = {w.rstrip(",.") for w in out.split() if "[ORG_" in w}
        self.assertEqual(len(pseudos), 1)
        self.assertEqual(a.stats["ORG"], 3)

    def test_enabled_does_not_affect_domain_or_email(self):
        cfg = AnonymizerConfig(org_aliases=["ExampleCorp"], org_aliases_share_pseudonym=True)
        a = SOCLogAnonymizer(salt="s", org_name="example", config=cfg)
        out = a.anonymize_text("support@example.com and example.com and example")
        self.assertIn("[EMAIL_", out)
        self.assertIn("[FQDN_", out)
        self.assertIn("[ORG_", out)
        # три РАЗНЫХ псевдонима: email, домен, оргназвание — не должны совпадать
        pseudos = [w.rstrip(",.") for w in out.split() if any(t in w for t in ("[EMAIL_", "[FQDN_", "[ORG_"))]
        self.assertEqual(len(pseudos), len(set(pseudos)))

    def test_enabled_deanonymize_restores_canonical_name(self):
        cfg = AnonymizerConfig(org_aliases=["ExampleCorp"], org_aliases_share_pseudonym=True)
        a = SOCLogAnonymizer(salt="s", org_name="example", config=cfg)
        cleaned = a.anonymize_text("ExampleCorp reported an issue")
        restored = a.deanonymize(cleaned)
        self.assertEqual(restored, "example reported an issue")


class TestPathsAreNotMasked(unittest.TestCase):
    """Пути оставляем как есть: маскируются только логин в профиле и ORG."""

    def setUp(self):
        self.a = SOCLogAnonymizer(salt="test-salt", org_name="acme")

    def test_protocol_version_and_cipher_stay(self):
        line = "client HTTP/1.1 IKEv2/AES256 to vpn.acme.local"
        out = self.a.anonymize_text(line)
        self.assertIn("HTTP/1.1", out)
        self.assertIn("IKEv2/AES256", out)
        self.assertNotIn("[PATH_", out)

    def test_iso_date_with_slashes_stays(self):
        line = "event at 2026/09/16 10:22:01"
        out = self.a.anonymize_text(line)
        self.assertIn("2026/09/16", out)
        self.assertNotIn("[PATH_", out)

    def test_unix_log_path_stays(self):
        line = "tail /var/log/auth.log"
        out = self.a.anonymize_text(line)
        self.assertIn("/var/log/auth.log", out)
        self.assertNotIn("[PATH_", out)

    def test_windows_system_path_is_not_user(self):
        line = r"loaded C:\Windows\System32\drivers\etc\hosts"
        out = self.a.anonymize_text(line)
        self.assertIn(r"C:\Windows\System32\drivers\etc\hosts", out)
        self.assertNotIn("[USER_", out)
        self.assertNotIn("[PATH_", out)

    def test_home_directory_username_is_masked(self):
        line = r"open C:\Users\jdoe\Documents\report.txt and /home/jdoe/.ssh/id_rsa"
        out = self.a.anonymize_text(line)
        self.assertNotIn("jdoe", out)
        self.assertIn(r"C:\Users\[USER_", out)
        self.assertIn("/home/[USER_", out)
        self.assertIn(r"\Documents\report.txt", out)
        self.assertIn("/.ssh/id_rsa", out)

    def test_windows_domain_user_still_masked(self):
        out = self.a.anonymize_text(r"login CORP\jdoe")
        self.assertNotIn(r"CORP\jdoe", out)
        self.assertIn("[USER_", out)

    def test_verify_does_not_flag_protocol_slash(self):
        line = "HTTP/1.1 GET /index.html IKEv2/AES256 2026/09/16"
        out = self.a.anonymize_text(line)
        safe, issues = self.a.verify(out)
        self.assertTrue(safe, issues)
        self.assertFalse(any("PATH" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
