"""
Конфигурация SOC Log Anonymizer.

Все настраиваемые параметры (список чувствительных JSON-ключей,
доменные суффиксы, телефонные префиксы, well-known SID, параметры
защиты соли и таймаут regex-обработки) вынесены сюда, чтобы каждая
команда могла адаптировать анонимизатор под свою инфраструктуру без
правки кода — через JSON- или INI-файл конфигурации.
"""

import configparser
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


def _default_sensitive_json_keys() -> List[str]:
    return [
        "user", "username", "login", "account", "subjectaccountname", "targetusername",
        "ip", "ipaddress", "src_ip", "dest_ip", "sourceip", "destinationip", "client_ip",
        "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
        "email", "phone", "domain", "computername", "host", "hostname",
    ]


def _default_key_type_hints() -> Dict[str, str]:
    return {
        "ip": "IP", "ipaddress": "IP", "srcip": "IP", "destip": "IP",
        "sourceip": "IP", "destinationip": "IP", "clientip": "IP",
        "email": "EMAIL",
        "domain": "FQDN", "computername": "FQDN", "host": "FQDN", "hostname": "FQDN",
        "user": "USER", "username": "USER", "login": "USER", "account": "USER",
        "subjectaccountname": "USER", "targetusername": "USER",
        "password": "SECRET", "passwd": "SECRET", "secret": "SECRET",
        "token": "SECRET", "apikey": "SECRET", "authorization": "SECRET",
        "phone": "PHONE",
    }


def _default_well_known_sids() -> List[str]:
    return [
        "S-1-1-0",       # Everyone
        "S-1-5-18",      # Local System
        "S-1-5-19",      # Local Service
        "S-1-5-20",      # Network Service
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-545",  # Users
        "S-1-5-32-546",  # Guests
        "S-1-5-32-547",  # Power Users
        "S-1-5-32-551",  # Backup Operators
    ]


def _default_phone_prefixes() -> List[str]:
    return ["+375", "+7", "8029", "8044", "8033", "8025", "+1"]


def _default_fqdn_tlds() -> List[str]:
    return ["by", "com", "ru", "org", "net", "lan", "corp", "local",
            "internal", "gov", "io", "info", "edu", "mil", "biz", "co"]


def _default_cef_fields() -> List[str]:
    return ["src", "dst", "suser", "duser", "cs1", "cs2", "cs3", "cs4", "shost", "dhost"]


# Поля-списки и поля-словари требуют отдельной (де)сериализации при работе
# с INI-форматом (у которого нет нативных списков/словарей).
_LIST_FIELDS = {
    "sensitive_json_keys", "well_known_sids", "phone_prefixes", "fqdn_tlds", "cef_fields",
    "org_aliases",
}
_DICT_FIELDS = {"key_type_hints"}


@dataclass
class AnonymizerConfig:
    """Настройки анонимизатора. Все поля можно переопределить через
    JSON- или INI-файл (см. AnonymizerConfig.load / AnonymizerConfig.save)."""

    org_name: str = "bank"
    hash_len: int = 12  # длина усечения HMAC-SHA256 в hex-символах
    max_token_len: int = 500  # ограничение длины захватываемого значения в key=value паттернах
    max_input_size_mb: int = 500  # порог предупреждения о большом файле перед загрузкой целиком в память

    # Число итераций PBKDF2-HMAC-SHA256 для растяжения соли перед
    # использованием её как HMAC-ключа. Повышает стоимость словарной
    # атаки на экспортированный mapping-файл почти бесплатно по коду.
    # 600_000 соответствует актуальной (2023+) рекомендации OWASP для
    # чистого PBKDF2-HMAC-SHA256 — компромисс между стойкостью и
    # задержкой при старте (выполняется один раз при создании
    # SOCLogAnonymizer, не на каждое значение).
    pbkdf2_iterations: int = 600_000

    # Максимальное время (в секундах) на анонимизацию одного текстового
    # блока/строки. Защита от потенциального ReDoS на специально
    # сконструированном входе — см. anonymizer.py, docstring anonymize_text.
    # None отключает защиту (не рекомендуется для недоверенного входа).
    regex_timeout_seconds: Optional[float] = 5.0

    # Верхняя граница числа одновременно живущих "зависших" (превысивших
    # regex_timeout_seconds и всё ещё выполняющихся) фоновых потоков.
    # Ограничивает рост потребления памяти/потоков процессом при
    # систематической подаче вредоносного входа — см. anonymizer.py,
    # docstring модуля, пункт 6. None отключает ограничение.
    max_orphaned_regex_threads: Optional[int] = 50

    # Путь к JSON Lines аудиторскому журналу операций (см. audit.py):
    # кто, когда, сколько значений какого типа заменил — без единого
    # исходного значения или псевдонима. None (по умолчанию) — аудит
    # отключён; это осознанный opt-in, а не поведение "из коробки", так
    # как факт ведения такого журнала и его расположение — решение
    # конкретного развёртывания/комплаенс-требований, а не библиотеки.
    audit_log_path: Optional[str] = None

    # Ротация аудиторского журнала (тот же механизм, что у --log-file:
    # logging.handlers.RotatingFileHandler) — без неё файл рос бы
    # неограниченно на долгоживущем развёртывании. По умолчанию — те же
    # лимиты, что и у --log-file (5 МБ × 5 файлов).
    audit_log_max_bytes: int = 5_000_000
    audit_log_backup_count: int = 5

    # Альтернативные написания/сокращения названия организации (например,
    # ["Bank of Example", "BoE", "ExampleBank"] при org_name="example") —
    # маскируются наравне с org_name. Пустой список по умолчанию: одно
    # только org_name может не покрывать реальные вариации написания в
    # логах (регистр/пробелы/CamelCase уже покрываются самим паттерном
    # ORG, но не синонимы и сокращения).
    org_aliases: List[str] = field(default_factory=list)

    sensitive_json_keys: List[str] = field(default_factory=_default_sensitive_json_keys)
    key_type_hints: Dict[str, str] = field(default_factory=_default_key_type_hints)
    well_known_sids: List[str] = field(default_factory=_default_well_known_sids)
    nil_guid: str = "00000000-0000-0000-0000-000000000000"
    phone_prefixes: List[str] = field(default_factory=_default_phone_prefixes)
    fqdn_tlds: List[str] = field(default_factory=_default_fqdn_tlds)
    cef_fields: List[str] = field(default_factory=_default_cef_fields)

    # Используется только GUI: время бездействия (в минутах), после
    # которого таблица соответствия автоматически очищается из памяти.
    session_timeout_minutes: int = 20

    # ------------------------------------------------------------------
    # Загрузка / сохранение
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[str]) -> "AnonymizerConfig":
        """Загружает конфигурацию из JSON- или INI-файла (формат
        определяется по расширению: .ini/.cfg -> INI, иначе JSON).
        Отсутствующие поля берутся из значений по умолчанию. Если
        path is None — возвращает конфигурацию по умолчанию."""
        if not path:
            return cls()
        ext = os.path.splitext(path)[1].lower()
        if ext in (".ini", ".cfg"):
            data = cls._load_ini(path)
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        defaults = asdict(cls())
        defaults.update({k: v for k, v in data.items() if k in defaults})
        return cls(**defaults)

    @staticmethod
    def _load_ini(path: str) -> Dict:
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        if not parser.has_section("anonymizer"):
            return {}
        section = parser["anonymizer"]
        data: Dict = {}
        defaults = asdict(AnonymizerConfig())
        for key, raw_value in section.items():
            if key not in defaults:
                continue
            if key in _LIST_FIELDS:
                data[key] = [v.strip() for v in raw_value.split(",") if v.strip()]
            elif key in _DICT_FIELDS:
                pairs = [p.strip() for p in raw_value.split(",") if p.strip()]
                data[key] = dict(p.split(":", 1) for p in pairs if ":" in p)
            elif isinstance(defaults[key], bool):
                data[key] = section.getboolean(key)
            elif isinstance(defaults[key], int):
                data[key] = section.getint(key)
            elif isinstance(defaults[key], float):
                data[key] = section.getfloat(key)
            else:
                data[key] = raw_value
        return data

    def save(self, path: str) -> None:
        """Сохраняет текущую конфигурацию в JSON- или INI-файл (по
        расширению пути), человекочитаемо, удобно версионировать рядом
        с кодом в git."""
        ext = os.path.splitext(path)[1].lower()
        if ext in (".ini", ".cfg"):
            self._save_ini(path)
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, ensure_ascii=False, indent=2)
            f.write("\n")

    def _save_ini(self, path: str) -> None:
        parser = configparser.ConfigParser()
        parser.add_section("anonymizer")
        for key, value in asdict(self).items():
            if key in _LIST_FIELDS:
                parser.set("anonymizer", key, ",".join(value))
            elif key in _DICT_FIELDS:
                parser.set("anonymizer", key, ",".join(f"{k}:{v}" for k, v in value.items()))
            else:
                parser.set("anonymizer", key, str(value))
        with open(path, "w", encoding="utf-8") as f:
            parser.write(f)

    def as_dict(self) -> Dict:
        return asdict(self)

    # ------------------------------------------------------------------
    # Валидация
    # ------------------------------------------------------------------

    def validate(self) -> List[str]:
        """Проверяет конфигурацию на очевидные ошибки, которые могли бы
        привести к "тихой" дыре в маскировании (например, пустой список
        TLD -> ни один домен не распознаётся). Возвращает список проблем;
        пустой список означает, что конфигурация выглядит корректно."""
        issues: List[str] = []

        if not self.org_name or not self.org_name.strip():
            issues.append("org_name пуст — наименование организации не будет маскироваться.")

        if not (4 <= self.hash_len <= 64):
            issues.append(f"hash_len={self.hash_len} вне разумного диапазона [4, 64].")

        if self.max_token_len < 1:
            issues.append("max_token_len должен быть положительным.")

        if self.max_input_size_mb < 1:
            issues.append("max_input_size_mb должен быть положительным.")

        if self.pbkdf2_iterations < 10_000:
            issues.append(
                f"pbkdf2_iterations={self.pbkdf2_iterations} — подозрительно мало "
                f"(рекомендуется >= 100_000) для растяжения соли."
            )

        if self.regex_timeout_seconds is not None and self.regex_timeout_seconds <= 0:
            issues.append("regex_timeout_seconds должен быть положительным или None.")

        if self.max_orphaned_regex_threads is not None and self.max_orphaned_regex_threads < 1:
            issues.append("max_orphaned_regex_threads должен быть положительным или None.")

        if self.audit_log_max_bytes < 1:
            issues.append("audit_log_max_bytes должен быть положительным.")
        if self.audit_log_backup_count < 0:
            issues.append("audit_log_backup_count не может быть отрицательным.")

        if any(not alias.strip() for alias in self.org_aliases):
            issues.append("org_aliases содержит пустую строку — она будет проигнорирована при построении паттерна.")

        if not self.sensitive_json_keys:
            issues.append("sensitive_json_keys пуст — чувствительные JSON-поля не будут распознаны.")

        if not self.fqdn_tlds:
            issues.append("fqdn_tlds пуст — доменные имена не будут распознаваться.")

        if not self.phone_prefixes:
            issues.append("phone_prefixes пуст — номера телефонов не будут распознаваться.")

        if not self.cef_fields:
            issues.append("cef_fields пуст — CEF/syslog key=value поля не будут распознаваться.")

        try:
            import re
            re.compile(r'\b' + re.escape(self.nil_guid) + r'\b')
        except re.error as e:
            issues.append(f"nil_guid некорректен как строка для сравнения: {e}")

        for tag, hint in self.key_type_hints.items():
            if not isinstance(hint, str) or not hint:
                issues.append(f"key_type_hints[{tag!r}] имеет некорректное значение: {hint!r}")

        return issues
