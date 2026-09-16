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
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def normalize_key(key: str) -> str:
    """Return the canonical form used for JSON keys and type hints."""
    return "".join(ch for ch in str(key).casefold() if ch.isalnum())


def _normalize_custom_pattern_entry(name: str, value: Any) -> Dict[str, Any]:
    """Normalize a custom pattern spec from a simple regex string or a dict."""
    if isinstance(value, str):
        return {
            "name": str(name or "CUSTOM").strip(),
            "pattern": value,
            "type": (str(name or "CUSTOM")).upper().strip(),
            "strategy": "full",
            "priority": 0,
            "enabled": True,
        }
    if isinstance(value, dict):
        normalized = dict(value)
        normalized.setdefault("name", str(name or normalized.get("tag") or "CUSTOM").strip())
        normalized.setdefault("pattern", normalized.get("regex") or normalized.get("value"))
        normalized.setdefault("type", (str(normalized.get("tag") or normalized.get("name") or "CUSTOM")).upper().strip())
        normalized.setdefault("strategy", "full")
        normalized.setdefault("priority", 0)
        normalized.setdefault("enabled", True)
        return normalized
    raise TypeError(f"custom_patterns[{name!r}] must be a regex string or a mapping, got {type(value).__name__}")


def _normalize_custom_pattern_map(custom_patterns: Any) -> Dict[str, Dict[str, Any]]:
    if not custom_patterns:
        return {}
    if isinstance(custom_patterns, dict):
        return {str(k): _normalize_custom_pattern_entry(str(k), v) for k, v in custom_patterns.items()}
    if isinstance(custom_patterns, list):
        normalized = {}
        for entry in custom_patterns:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or entry.get("tag") or entry.get("type") or "CUSTOM").strip()
            normalized[name] = _normalize_custom_pattern_entry(name, entry)
        return normalized
    raise TypeError("custom_patterns must be a dict or list of dicts")


def _clean_field_names(values: List[str]) -> List[str]:
    """Trim configured text-field literals without changing separators."""
    result = []
    seen = set()
    for value in values:
        cleaned = str(value).strip()
        marker = cleaned.casefold()
        if cleaned and marker not in seen:
            result.append(cleaned)
            seen.add(marker)
    return result


def _app_dir() -> str:
    """Каталог, в котором физически лежит запущенное приложение — рядом
    с которым ищется auto-discovered конфиг (см. find_default_config_path).

    Для PyInstaller `--onefile` сборки `sys.executable` указывает на сам
    .exe/бинарник (тот, который пользователь скачал и запустил), а НЕ на
    временный каталог распаковки `sys._MEIPASS`, куда PyInstaller на
    время выполнения разворачивает bundled-файлы: этот каталог новый при
    каждом запуске и удаляется по завершении процесса — положить туда
    конфиг и рассчитывать, что он "останется", бессмысленно. `frozen`
    выставляется в True самим PyInstaller (и другими фризерами вроде
    cx_Freeze) именно для этого различения.

    Для обычного запуска (`python -m soc_log_anonymizer`, `pip install
    -e .`, zipapp) — каталог, где лежит сам пакет; это менее интуитивно
    как "рядом с приложением" для конечного пользователя, чем для
    собранного .exe, но даёт предсказуемое поведение без дополнительных
    предположений о структуре проекта/venv."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# Имена файлов, которые auto-discovery ищет рядом с приложением, в
# порядке приоритета (JSON раньше INI — формат по умолчанию для
# --save-mapping и большинства примеров в README).
_AUTO_CONFIG_NAMES = ("soc_log_anonymizer.json", "soc_log_anonymizer.ini")


def find_default_config_path() -> Optional[str]:
    """Ищет конфигурационный файл рядом с запущенным приложением (см.
    `_app_dir`) — позволяет просто положить `soc_log_anonymizer.json`
    (или `.ini`) в папку с `.exe`/скриптом один раз, без необходимости
    каждый раз указывать `--config` или переменную окружения
    `SOC_ANON_CONFIG`; при каждом новом запуске файл перечитывается
    заново (это просто следствие того, что и CLI, и GUI вызывают эту
    функцию заново при старте процесса — никакого отдельного
    "слежения" за файлом во время работы не требуется и не делается).

    Явный `--config`/`SOC_ANON_CONFIG` в CLI и явная загрузка через
    диалог "⚙ Конфиг" в GUI имеют приоритет над этим автопоиском — он
    используется только как запасной вариант, когда ничего явно не
    указано. Возвращает None, если ничего не найдено — тогда
    используется конфигурация по умолчанию, как и раньше."""
    app_dir = _app_dir()
    for name in _AUTO_CONFIG_NAMES:
        candidate = os.path.join(app_dir, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _default_sensitive_json_keys() -> List[str]:
    return [
        "user", "username", "login", "account", "subjectaccountname", "targetusername",
        "objectaccountname", "subjectaccountdomain", "objectaccountdomain",
        "ip", "ipaddress", "src_ip", "dest_ip", "sourceip", "destinationip", "client_ip",
        "srcip", "dstip",
        "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
        "email", "phone", "domain", "computername", "host", "hostname", "srchost", "dsthost",
    ]


def _default_key_type_hints() -> Dict[str, str]:
    return {
        "ip": "IP", "ipaddress": "IP", "srcip": "IP", "destip": "IP", "dstip": "IP",
        "sourceip": "IP", "destinationip": "IP", "clientip": "IP",
        "email": "EMAIL",
        "domain": "FQDN", "computername": "FQDN", "host": "FQDN", "hostname": "FQDN",
        "srchost": "FQDN", "dsthost": "FQDN",
        "user": "USER", "username": "USER", "login": "USER", "account": "USER",
        "subjectaccountname": "USER", "targetusername": "USER", "objectaccountname": "USER",
        "subjectaccountdomain": "USER", "objectaccountdomain": "USER",
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
    return [
        "src", "dst", "suser", "duser", "cs1", "cs2", "cs3", "cs4", "shost", "dhost",
        # Cisco ASA/IOS и Checkpoint нередко используют эти имена вместо
        # "канонических" CEF src/dst/shost/dhost для тех же самых
        # IP-адресов/хостов.
        "src_ip", "dst_ip", "srcip", "dstip", "orig", "origin", "peer_gateway",
    ]


def _default_user_field_names() -> List[str]:
    """Имена полей в свободном тексте key=value / key: value, после
    которых значение считается именем пользователя/учётной записи (тег
    USER), даже если само значение не похоже ни на один более
    специфичный формат (просто "admin"/"root"/"jdoe" и т.п. — без этого
    списка такое значение классифицировалось бы как generic VALUE, см.
    _hash_classified в anonymizer.py). Помимо стандартных user/login,
    сюда включены поля, характерные для Cisco ASA/IOS ("uname" в
    сообщениях смены привилегий), Checkpoint ("subject" в audit-логах
    SmartCenter) и парных src/dst-полей, которыми Cisco/Checkpoint часто
    заменяют "canonical" CEF suser/duser."""
    return [
        "user", "username", "login", "account", "subject.account.name",
        "uname", "subject", "src_user", "dst_user", "srcuser", "dstuser",
        "target_user", "targetuser", "accountname", "object.account.name",
    ]


def _default_cef_user_fields() -> List[str]:
    """Подмножество cef_fields, которое семантически ВСЕГДА username
    (а не адрес/хост) — используется ТОЛЬКО для выбора отката типа в
    CEF_KV (см. anonymizer.py::_sub_cef_kv), не для отдельного паттерна.
    Не должно пересекаться по значениям с user_field_names: те поля уже
    целиком обрабатываются паттерном CEF_KV (раз они в cef_fields), и
    добавление их же в user_field_names заставило бы ОТДЕЛЬНЫЙ паттерн
    USER_FIELD повторно "обработать" уже подставленный псевдоним как
    новое сырое значение — ломая консистентную психевдонимизацию."""
    return ["suser", "duser"]


def _default_secret_field_names() -> List[str]:
    return ["password", "passwd", "secret", "api_key", "apikey", "token", "auth_key", "bearer"]


# Поля-списки и поля-словари требуют отдельной (де)сериализации при работе
# с INI-форматом (у которого нет нативных списков/словарей).
_LIST_FIELDS = {
    "sensitive_json_keys", "well_known_sids", "phone_prefixes", "fqdn_tlds", "cef_fields",
    "org_aliases", "user_field_names", "secret_field_names", "cef_user_fields",
    "allowlist", "fqdn_stopwords",
}
_DICT_FIELDS = {"key_type_hints", "custom_patterns"}


@dataclass
class AnonymizerConfig:
    """Настройки анонимизатора. Все поля можно переопределить через
    JSON- или INI-файл (см. AnonymizerConfig.load / AnonymizerConfig.save)."""

    org_name: str = "bank"
    config_version: int = 1
    custom_patterns: Dict[str, Any] = field(default_factory=dict)
    context_rules: List[Dict[str, Any]] = field(default_factory=list)
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

    # По умолчанию org_name и каждый org_alias — это РАЗНЫЕ строки, значит
    # разный HMAC-хэш и разный псевдоним, даже если по смыслу это одна и
    # та же организация. Если True — все буквальные упоминания (org_name
    # и любой из org_aliases) сходятся к ОДНОМУ псевдониму, посчитанному
    # от org_name (см. anonymizer.py::_sub_org).
    #
    # ВАЖНО: это касается ТОЛЬКО буквальных текстовых упоминаний
    # организации как отдельного слова (паттерн ORG). Домены/email, в
    # которых название организации входит как часть строки (например
    # "example.com", "user@example.com"), продолжают обрабатываться
    # самостоятельными паттернами FQDN/EMAIL — эти паттерны применяются
    # РАНЬШЕ ORG и получают свой ОТДЕЛЬНЫЙ псевдоним на каждое уникальное
    # доменное имя/email, независимо от значения этого флага. Флаг не
    # объединяет ORG-псевдоним с FQDN/EMAIL-псевдонимами ни в каком виде.
    #
    # Trade-off при включении: деанонимизация `[ORG_...]` всегда
    # восстанавливает КАНОНИЧЕСКОЕ org_name, а не тот конкретный алиас,
    # который встретился именно в этом месте текста (если это важно —
    # оставьте флаг выключенным, псевдонимы останутся раздельными, но
    # точно обратимыми на каждый алиас в отдельности).
    org_aliases_share_pseudonym: bool = False

    sensitive_json_keys: List[str] = field(default_factory=_default_sensitive_json_keys)
    key_type_hints: Dict[str, str] = field(default_factory=_default_key_type_hints)
    well_known_sids: List[str] = field(default_factory=_default_well_known_sids)
    nil_guid: str = "00000000-0000-0000-0000-000000000000"
    phone_prefixes: List[str] = field(default_factory=_default_phone_prefixes)
    fqdn_tlds: List[str] = field(default_factory=_default_fqdn_tlds)
    cef_fields: List[str] = field(default_factory=_default_cef_fields)

    # Имена полей в свободном тексте (key=value / key: value), после
    # которых значение форсированно считается username/секретом, даже
    # если само значение не похоже ни на один более специфичный формат
    # (см. _default_user_field_names/_default_secret_field_names выше и
    # anonymizer.py::_hash_classified). Отдельно от cef_fields — те
    # предназначены для полей, значение которых нужно КЛАССИФИЦИРОВАТЬ
    # по формату (обычно адреса/хосты), а не форсированно типизировать.
    user_field_names: List[str] = field(default_factory=_default_user_field_names)
    secret_field_names: List[str] = field(default_factory=_default_secret_field_names)

    # Подмножество cef_fields, семантически всегда username (см.
    # _default_cef_user_fields выше) — НЕ для отдельного паттерна, только
    # для выбора отката типа внутри CEF_KV.
    cef_user_fields: List[str] = field(default_factory=_default_cef_user_fields)

    # Используется только GUI: время бездействия (в минутах), после
    # которого таблица соответствия автоматически очищается из памяти.
    session_timeout_minutes: int = 20

    # Values that must stay unmasked (exact match, case-insensitive).
    allowlist: List[str] = field(default_factory=list)
    fqdn_stopwords: List[str] = field(default_factory=list)

    # Free-text HASH matches only near hash/md5/sha/ntlm/… keywords.
    hash_require_context: bool = True
    # Join syslog backslash-continuations and indented traceback lines.
    multiline_join: bool = True
    # Split CEF/LEEF extensions and RFC5424 hostname before generic regex.
    parse_structured: bool = True
    # If original JSON has no newlines, dump compact (do not force indent=2).
    json_preserve_formatting: bool = True

    def normalize_keys(self) -> "AnonymizerConfig":
        """Normalize configured field names consistently across JSON/INI input."""
        self.sensitive_json_keys = [normalize_key(v) for v in self.sensitive_json_keys if str(v).strip()]
        self.key_type_hints = {normalize_key(k): str(v).upper().strip()
                               for k, v in self.key_type_hints.items() if str(k).strip()}
        # These values are embedded as escaped literals in key=value regexes;
        # preserve `_`, `-`, and `.` (for example `src_ip`).
        self.user_field_names = _clean_field_names(self.user_field_names)
        self.secret_field_names = _clean_field_names(self.secret_field_names)
        self.cef_fields = _clean_field_names(self.cef_fields)
        self.cef_user_fields = _clean_field_names(self.cef_user_fields)
        self.custom_patterns = _normalize_custom_pattern_map(self.custom_patterns)
        if isinstance(self.context_rules, list):
            self.context_rules = [dict(rule) for rule in self.context_rules if isinstance(rule, dict)]
        self.allowlist = [str(v).strip() for v in self.allowlist if str(v).strip()]
        self.fqdn_stopwords = [str(v).strip() for v in self.fqdn_stopwords if str(v).strip()]
        return self

    def iter_custom_patterns(self):
        """Return a normalized list of custom pattern specs in priority order."""
        specs = _normalize_custom_pattern_map(self.custom_patterns).values()
        return sorted(specs, key=lambda item: int(item.get("priority", 0)), reverse=True)

    # ------------------------------------------------------------------
    # Загрузка / сохранение
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Dict) -> "AnonymizerConfig":
        """Строит конфигурацию из произвольного словаря (например,
        распарсенного JSON), беря отсутствующие поля из значений по
        умолчанию и игнорируя незнакомые ключи (совместимость со старыми
        файлами конфигурации при добавлении новых полей). Используется
        и load() (чтение из файла), и GUI-редактором конфигурации
        (см. gui.py, вкладка "Конфигурация") — там источник тот же JSON,
        только пришедший из текстового поля, а не с диска."""
        defaults = asdict(cls())
        for key, value in data.items():
            if key in defaults:
                defaults[key] = value
        if "custom_patterns" in data and isinstance(data["custom_patterns"], list):
            defaults["custom_patterns"] = {str(i): item for i, item in enumerate(data["custom_patterns"])}
        return cls(**defaults).normalize_keys()

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
        return cls.from_dict(data)

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

        expected_types = {
            "config_version": int, "org_name": str, "hash_len": int,
            "max_token_len": int, "max_input_size_mb": int,
            "pbkdf2_iterations": int, "session_timeout_minutes": int,
            "sensitive_json_keys": list, "key_type_hints": dict,
            "cef_fields": list, "user_field_names": list,
            "secret_field_names": list,
            "custom_patterns": dict,
            "allowlist": list,
        }
        for name, expected in expected_types.items():
            value = getattr(self, name)
            if not isinstance(value, expected) or (
                    expected is int and isinstance(value, bool)):
                issues.append(f"{name} имеет неверный тип: ожидается {expected.__name__}.")
        if not isinstance(self.config_version, int) or self.config_version < 1:
            issues.append("config_version должен быть целым числом >= 1.")

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

        if not self.user_field_names:
            issues.append("user_field_names пуст — имена пользователей в key=value полях не будут распознаваться.")

        if not self.secret_field_names:
            issues.append("secret_field_names пуст — секреты в key=value полях не будут распознаваться.")

        unknown_cef_user = set(f.lower() for f in self.cef_user_fields) - set(f.lower() for f in self.cef_fields)
        if unknown_cef_user:
            issues.append(
                f"cef_user_fields содержит поля вне cef_fields: {sorted(unknown_cef_user)} — "
                f"они не будут распознаны паттерном CEF_KV и это условие никогда не сработает."
            )

        try:
            import re
            re.compile(r'\b' + re.escape(self.nil_guid) + r'\b')
        except re.error as e:
            issues.append(f"nil_guid некорректен как строка для сравнения: {e}")

        for tag, hint in self.key_type_hints.items():
            if not isinstance(hint, str) or not hint:
                issues.append(f"key_type_hints[{tag!r}] имеет некорректное значение: {hint!r}")
        import re
        for tag, expression in self.custom_patterns.items():
            if isinstance(expression, (str, dict)):
                normalized = _normalize_custom_pattern_entry(str(tag), expression)
                pattern = normalized.get("pattern")
                if not pattern:
                    issues.append(f"custom_patterns[{tag!r}] missing pattern/regex.")
                    continue
                try:
                    compiled = re.compile(pattern)
                except re.error as exc:
                    issues.append(f"custom_patterns[{tag!r}] invalid regex: {exc}")
                    continue

                test_string = normalized.get("test_string")
                if test_string is None or str(test_string) == "":
                    continue
                strategy = str(normalized.get("strategy") or "full").lower()
                subject = str(test_string)
                matched = bool(compiled.fullmatch(subject)) if strategy == "full" else bool(compiled.search(subject))
                if not matched:
                    issues.append(
                        f"custom_patterns[{tag!r}] does not match test_string={subject!r} "
                        f"for strategy={strategy!r}."
                    )
                continue
            issues.append("custom_patterns must be a dictionary with regex strings or pattern/regex mappings.")
        normalized_hints = {}
        for key, hint in self.key_type_hints.items():
            canonical = normalize_key(key)
            previous = normalized_hints.setdefault(canonical, hint)
            if previous != hint:
                issues.append(f"Конфликт key_type_hints для ключа {canonical!r}: {previous!r}/{hint!r}.")

        return issues
