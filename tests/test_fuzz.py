"""
Fuzz-тест на стандартном модуле `random` (без сторонних библиотек вроде
Hypothesis). Генерирует случайные лог-строки со случайно внедрёнными
IP/email/логинами/хэшами и проверяет инвариант: после anonymize()
gatekeeper verify() всегда должен считать результат безопасным.

Seed фиксирован — прогон детерминирован и воспроизводим (не flaky).
"""

import random
import string
import unittest

from soc_log_anonymizer.anonymizer import SOCLogAnonymizer

FUZZ_SEED = 20260830
FUZZ_ITERATIONS = 200


def _random_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(0, 255)) for _ in range(4))


def _random_email(rng: random.Random) -> str:
    user = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 10)))
    domain = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 8)))
    tld = rng.choice(["com", "net", "org", "local"])
    return f"{user}@{domain}.{tld}"


def _random_hash(rng: random.Random, length: int) -> str:
    return "".join(rng.choices("0123456789abcdef", k=length))


def _random_username(rng: random.Random) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(4, 12)))


def _random_free_word(rng: random.Random) -> str:
    return "".join(rng.choices(string.ascii_letters, k=rng.randint(3, 12)))


_GENERATORS = [
    lambda rng: _random_ip(rng),
    lambda rng: _random_email(rng),
    lambda rng: _random_hash(rng, 32),
    lambda rng: _random_hash(rng, 40),
    lambda rng: _random_hash(rng, 64),
    lambda rng: f"user={_random_username(rng)}",
    lambda rng: f"src={_random_ip(rng)}",
    lambda rng: f"password={_random_username(rng)}{rng.randint(0, 999)}",
]


def _generate_random_log_line(rng: random.Random) -> str:
    n_tokens = rng.randint(3, 10)
    tokens = []
    for _ in range(n_tokens):
        if rng.random() < 0.5:
            tokens.append(_random_free_word(rng))
        else:
            generator = rng.choice(_GENERATORS)
            tokens.append(generator(rng))
    return " ".join(tokens)


def _generate_random_log(rng: random.Random, n_lines: int) -> str:
    return "\n".join(_generate_random_log_line(rng) for _ in range(n_lines))


class TestFuzzAnonymization(unittest.TestCase):
    """Инвариант: anonymize() -> verify() должен всегда возвращать
    is_safe=True для случайно сгенерированных, но структурно ожидаемых
    логов (IP/email/hash/user/password в типичных форматах)."""

    def test_random_logs_always_pass_gatekeeper(self):
        rng = random.Random(FUZZ_SEED)
        failures = []

        for i in range(FUZZ_ITERATIONS):
            anonymizer = SOCLogAnonymizer(salt=f"fuzz-salt-{i}", org_name="bank",
                                           config=_fast_config())
            raw_log = _generate_random_log(rng, n_lines=rng.randint(1, 5))
            cleaned = anonymizer.anonymize_text(raw_log)
            is_safe, issues = anonymizer.verify(cleaned)
            if not is_safe:
                failures.append((i, raw_log, cleaned, issues))

        if failures:
            i, raw_log, cleaned, issues = failures[0]
            self.fail(
                f"Gatekeeper нашёл проблему в итерации {i} "
                f"(всего провалов: {len(failures)}/{FUZZ_ITERATIONS}).\n"
                f"Исходный текст: {raw_log!r}\n"
                f"После anonymize(): {cleaned!r}\n"
                f"Issues: {issues}"
            )

    def test_random_logs_roundtrip_deanonymize(self):
        """Дополнительный инвариант: anonymize() -> deanonymize() должен
        точно восстанавливать исходный текст (при условии, что таблица
        соответствия не была потеряна)."""
        rng = random.Random(FUZZ_SEED + 1)

        for i in range(50):
            anonymizer = SOCLogAnonymizer(salt=f"fuzz-roundtrip-{i}", org_name="bank",
                                           config=_fast_config())
            raw_log = _generate_random_log(rng, n_lines=rng.randint(1, 3))
            cleaned = anonymizer.anonymize_text(raw_log)
            restored = anonymizer.deanonymize(cleaned)
            self.assertEqual(restored, raw_log, msg=f"Roundtrip не совпал на итерации {i}")


def _fast_config():
    """Конфиг с минимальным числом итераций PBKDF2 — fuzz-тест создаёт
    много экземпляров SOCLogAnonymizer, дефолтные 200_000 итераций сделали
    бы прогон непрактично медленным. Безопасность здесь не тестируется,
    поэтому ускорение оправдано."""
    from soc_log_anonymizer.config import AnonymizerConfig
    return AnonymizerConfig(pbkdf2_iterations=100)


if __name__ == "__main__":
    unittest.main()
