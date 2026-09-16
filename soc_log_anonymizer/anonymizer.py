"""
SOC Log Anonymizer — основной модуль анонимизации логов перед отправкой
во внешнюю LLM. Только стандартная библиотека Python.

Ключевые принципы реализации (подробности — в README.md):

1. Консистентность псевдонимов: одно и то же значение (IP, email, хэш,
   логин и т.д.), где бы оно ни встретилось — в "голом" виде, в CEF
   key=value паре, в JSON-поле или после "password=" — получает ОДИН и
   тот же псевдоним. Достигается классификацией значения по типу
   (`_classify_value`) перед хэшированием, а не хэшированием "вслепую"
   по имени поля/ключа, в котором значение было найдено.

2. HMAC-SHA256(ключ, значение) вместо sha256(соль + значение). Ключ, в
   свою очередь, получается растяжением соли через PBKDF2-HMAC-SHA256
   (`config.pbkdf2_iterations` итераций) — это заметно повышает
   стоимость словарной атаки на экспортированный mapping-файл, если он
   попадёт в чужие руки вместе с исходной солью.

3. Защита от коллизий: при совпадении усечённого хэша для разных
   значений добавляется числовой суффикс псевдонима.

4. Обратимость: каждая замена фиксируется в mapping_table /
   reverse_mapping. Таблицу можно сохранить в JSON и загрузить в новом
   процессе (важно для CLI, где каждый запуск — новый процесс).

5. Не анонимизируются "общеизвестные" системные константы (nil GUID,
   well-known Windows SID) — их маскирование не повышает приватность,
   но лишает LLM полезного контекста.

6. Базовая защита от ReDoS: применение паттернов к одному текстовому
   блоку выполняется в отдельном потоке с таймаутом
   (`config.regex_timeout_seconds`). Python не даёt безопасно прервать
   уже выполняющийся regex-матчинг (GIL удерживается C-кодом модуля
   `re`), поэтому при превышении таймаута мы НЕ дожидаемся результата и
   НЕ возвращаем частично замаскированный текст (это было бы опасно —
   риск утечки), а возвращаем явный маркер и логируем предупреждение.
   "Зависший" поток остаётся daemon-потоком в фоне до завершения работы
   процесса — это утечка ресурсов в патологическом случае. Число таких
   одновременно живущих "зависших" потоков ограничено сверху
   (`config.max_orphaned_regex_threads`): при систематической подаче
   вредоносного входа (много блоков подряд, каждый вызывающий таймаут)
   инструмент перестаёт порождать новые потоки после достижения лимита
   и сразу возвращает маркер таймаута без попытки обработки — это
   ограничивает рост потребления памяти/потоков процессом сверху, не
   влияя на корректность и безопасность вывода на нормальном входе.

7. Регистрозависимость хэширования: большинство типов значений
   (IP/EMAIL/FQDN/UUID/USER и т.д.) хэшируются в нижнем регистре — это
   осознанное решение ради консистентности псевдонимов (эти форматы
   регистронезависимы по своей природе или конвенции). Значения типа
   SECRET (пароли, токены, API-ключи) — исключение: регистр в них
   значим и является частью самого секрета, поэтому они хэшируются в
   исходном регистре (см. `SOCLogAnonymizer.CASE_SENSITIVE_TYPES`).

8. Кэш классификации значений (`_classify_value`) — на уровне
   ЭКЗЕМПЛЯРА, а не общеклассовый. Классификация зависит от паттернов
   конкретной конфигурации, поэтому общеклассовый кэш, ключующийся в
   т.ч. по самому экземпляру (как в более ранней реализации), держал бы
   сильную ссылку на каждый созданный `SOCLogAnonymizer` до явного
   `cache_clear()` — утечка памяти при частом пересоздании экземпляров
   (типичный сценарий для GUI при смене соли/конфигурации). Инстанс-кэш
   такой проблемы не создаёт: он живёт и умирает вместе с экземпляром и
   дополнительно явно очищается в `clear_sensitive_data()`.

Пример использования (доступен через `python -m doctest`):

    >>> cfg = AnonymizerConfig(pbkdf2_iterations=1000)  # низкое число итераций — только для быстрого примера
    >>> a = SOCLogAnonymizer(salt="doctest-salt", org_name="bank", config=cfg)
    >>> out = a.anonymize_text("src=192.168.1.10 user=jdoe")
    >>> "192.168.1.10" in out
    False
    >>> "jdoe" in out
    False
    >>> restored = a.deanonymize(out)
    >>> restored == "src=192.168.1.10 user=jdoe"
    True
"""

import gc
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from .config import AnonymizerConfig
from .detectors import (
    DEFAULT_FQDN_STOPWORDS,
    is_allowlisted,
    is_plausible_fqdn,
    is_plausible_free_text_hash,
    is_plausible_phone,
    is_plausible_windows_user,
)
from .io_utils import check_world_readable
from .result import AnonymizeResult
from .structured import join_continued_lines, mask_structured_line

logger = logging.getLogger("soc_log_anonymizer")

_TIMEOUT_MARKER = "[ANONYMIZATION_TIMEOUT: содержимое скрыто из соображений безопасности, {n} символов]"

# Версия формата mapping-файла (save_mapping/load_mapping). Файлы без
# явного schema_version считаются версией 0 (созданы до введения
# версионирования) — обратная совместимость сохраняется, но будущие
# несовместимые изменения формата смогут явно об этом предупредить,
# вместо того чтобы молча падать или тихо портить данные.
MAPPING_SCHEMA_VERSION = 1


def _safe_str_eq(a: str, b: str) -> bool:
    """Сравнение строк через secrets.compare_digest (постоянное время)
    вместо обычного `==`. Практическая значимость для timing-атак здесь
    невелика (значения не секрет для собственного процесса), но это
    сравнение хэш-подобных строк (псевдонимов), и постоянное время —
    правильная гигиена по умолчанию для такого сравнения."""
    try:
        return secrets.compare_digest(a, b)
    except TypeError:
        return a == b


class SOCLogAnonymizer:
    """Анонимизатор логов для SOC-аналитиков (только стандартная библиотека)."""

    __slots__ = (
        "config", "salt", "_hmac_key", "_hash_cache", "mapping_table",
        "reverse_mapping", "stats", "well_known_sids", "nil_guid",
        "custom_pattern_metadata", "patterns", "patterns_dict", "_classify_cache",
        "_orphaned_thread_count", "_orphaned_thread_lock", "_cef_user_fields_lower",
        "__weakref__",
    )

    # Порядок приоритета классификации "сырого" значения (из CEF/SECRET/
    # USER_FIELD/JSON) по конкретному типу данных. Порядок важен: более
    # специфичные форматы должны проверяться раньше более общих.
    CLASSIFY_ORDER = [
        "JWT", "SID", "HASH", "UUID", "MAC", "IP_NET", "IP", "EMAIL", "USER", "FQDN", "PHONE",
        "URL", "TOKEN", "CLOUD_SECRET", "SSH_KEY", "CONN_STR",
    ]

    # Типы значений, для которых регистр значим и НЕ приводится к нижнему
    # перед хэшированием (см. пункт 7 в docstring модуля).
    CASE_SENSITIVE_TYPES = frozenset({"SECRET", "B64_CMD"})

    # Верхняя граница размера инстанс-кэша классификации, чтобы он не рос
    # неограниченно на очень больших/разнообразных логах в рамках одного
    # долгоживущего экземпляра (например, в GUI-сессии).
    _CLASSIFY_CACHE_MAX_SIZE = 100_000

    def __init__(self, salt: Optional[str] = None, org_name: Optional[str] = None,
                 config: Optional[AnonymizerConfig] = None,
                 _prederived_key: Optional[bytes] = None):
        self.config = config or AnonymizerConfig()
        if org_name:
            self.config.org_name = org_name

        # Соль используется как исходный материал для PBKDF2 (см. ниже),
        # а не напрямую как HMAC-ключ.
        self.salt = salt if salt else secrets.token_hex(16)

        if _prederived_key is not None:
            # Внутренний путь для параллельных воркеров (см.
            # anonymize_parallel_lines/_parallel_worker и cli.py
            # _batch_worker): PBKDF2 — детерминированная функция от
            # (salt, iterations), поэтому если ключ уже был выведен один
            # раз в родительском процессе для этой же соли, повторный
            # прогон 600 000 итераций в КАЖДОМ дочернем процессе/на
            # каждый чанк/файл — чистые накладные расходы. При батче из
            # сотен файлов или потоковой обработке из десятков чанков это
            # заметная доля общего времени именно там, где параллелизм
            # включают ради скорости. Параметр приватный (префикс `_`,
            # не часть публичного API) — вызывающий код обязан гарантировать,
            # что ключ действительно выведен из ТОЙ ЖЕ соли и тех же
            # `pbkdf2_iterations`, иначе получит тихо неверные псевдонимы.
            self._hmac_key = _prederived_key
        else:
            # Растяжение соли через PBKDF2-HMAC-SHA256 перед использованием
            # как ключа HMAC — повышает стоимость offline-перебора, если
            # экспортированный mapping-файл (содержащий соль в открытом виде)
            # попадёт в чужие руки. Выполняется один раз при создании
            # экземпляра, а не на каждое хэшируемое значение.
            self._hmac_key = hashlib.pbkdf2_hmac(
                "sha256", self.salt.encode("utf-8"), b"soc-log-anonymizer",
                self.config.pbkdf2_iterations,
            )

        self._hash_cache: Dict[str, str] = {}
        self.mapping_table: Dict[str, str] = {}   # Original -> Pseudonym
        self.reverse_mapping: Dict[str, str] = {}  # Pseudonym -> Original
        self.stats: Counter = Counter()            # тип -> число замен (occurrences)

        self.well_known_sids = {s.upper() for s in self.config.well_known_sids}
        self.nil_guid = self.config.nil_guid.lower()

        self.custom_pattern_metadata: Dict[str, Dict[str, Any]] = {}
        self.patterns: List[Tuple[str, "re.Pattern"]] = self._build_patterns()
        self.patterns_dict: Dict[str, "re.Pattern"] = dict(self.patterns)

        # Быстрый lookup для _sub_cef_kv: некоторые CEF-поля (suser, duser)
        # семантически ВСЕГДА username, а не просто "поле для
        # классификации по формату" — им нужен тот же откат типа (USER),
        # что и явным USER_FIELD-совпадениям, иначе одно и то же значение
        # ("jdoe"), встреченное и как "suser=jdoe", и как "user=jdoe",
        # получило бы РАЗНЫЕ псевдонимы (разный tag => разный HMAC-контекст
        # => разный хэш) — нарушая консистентную психевдонимизацию,
        # см. test_username_consistent_cef_kv_and_user_field.
        #
        # Намеренно строится из config.cef_user_fields, а НЕ из
        # config.user_field_names: поля из cef_user_fields УЖЕ целиком
        # обрабатываются паттерном CEF_KV (они входят в cef_fields) — если
        # бы они ТАКЖЕ были в user_field_names, отдельный паттерн
        # USER_FIELD повторно "нашёл" бы уже подставленный CEF_KV
        # псевдоним в тексте и хэшировал бы его ещё раз как новое сырое
        # значение (двойная анонимизация одного и того же поля).
        self._cef_user_fields_lower = {f.lower() for f in self.config.cef_user_fields}

        # Кэш классификации значений — на уровне экземпляра (см. пункт 8
        # в docstring модуля), а не общеклассовый lru_cache.
        self._classify_cache: Dict[str, str] = {}

        # Счётчик "зависших" (превысивших таймаут и всё ещё работающих)
        # потоков анонимизации текста — см. anonymize_text() и пункт 6 в
        # docstring модуля.
        self._orphaned_thread_count = 0
        self._orphaned_thread_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Context manager — явная очистка чувствительных данных из памяти
    # ------------------------------------------------------------------

    def __enter__(self) -> "SOCLogAnonymizer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.clear_sensitive_data()

    def clear_sensitive_data(self) -> None:
        """Явно освобождает mapping_table/reverse_mapping/кэш хэшей и
        запрашивает сборку мусора. Python не гарантирует немедленную
        перезапись памяти (строки иммутабельны и могут какое-то время
        жить в памяти интерпретатора), но это снижает время жизни
        чувствительных данных в процессе по сравнению с ожиданием
        обычной сборки мусора."""
        self.mapping_table.clear()
        self.reverse_mapping.clear()
        self._hash_cache.clear()
        # Кэш классификации — на уровне экземпляра (см. __init__), очистка
        # затрагивает только этот экземпляр и не влияет на другие активные
        # SOCLogAnonymizer в том же процессе.
        self._classify_cache.clear()
        gc.collect()

    # ------------------------------------------------------------------
    # Построение паттернов на основе конфигурации
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_json_key(key: str) -> str:
        """Нормализует имя JSON-ключа для сопоставления с конфигурацией.

        Разные источники логов используют разные разделители в одном и том
        же имени поля (например, ``src_ip``, ``src-ip`` и ``src.ip``).
        """
        return key.lower().replace("_", "").replace("-", "").replace(".", "")

    def _build_patterns(self) -> List[Tuple[str, "re.Pattern"]]:
        cef_alt = "|".join(re.escape(f) for f in self.config.cef_fields)
        secret_alt = "|".join(re.escape(f) for f in self.config.secret_field_names)
        user_alt = "|".join(re.escape(f) for f in self.config.user_field_names)
        phone_alt = "|".join(re.escape(p) for p in self.config.phone_prefixes)
        tld_alt = "|".join(re.escape(t) for t in self.config.fqdn_tlds)
        n = self.config.max_token_len

        # Паттерны применяются к тексту СТРОГО в этом порядке. Порядок
        # выбран так, чтобы:
        #  - структурные форматы (JWT, base64-команды) обрабатывались первыми;
        #  - key=value конструкции (CEF_KV/SECRET/USER_FIELD) обрабатывались
        #    ДО generic-паттернов (IP/EMAIL/...), чтобы их "сырое" значение
        #    можно было классифицировать и хэшировать единым образом;
        #  - наименование организации (ORG) — в самом конце.
        # Негативный lookbehind против ложных срабатываний SECRET/USER_FIELD
        # на обычных английских фразах вида "Invalid password" (сообщение
        # об ошибке, не поле!) — если после такой фразы ГДЕ-ТО дальше в
        # строке встречается НЕСВЯЗАННЫЙ разделитель полей (Cisco ASA
        # разделяет поля через " : ", например "reason = Invalid password
        # : server = 10.0.0.10"), без этой защиты regex ошибочно трактует
        # "password :" как key=value и хэширует СЛЕДУЮЩЕЕ слово ("server")
        # под тегом SECRET — реальной утечки при этом не происходит (сам
        # IP дальше по строке маскируется отдельно, generic-паттерном), но
        # вывод вводит в заблуждение (аналитик видит "замаскированный
        # секрет" там, где его никогда не было). Каждый префикс — фиксированной
        # длины (требование Python re для lookbehind), поэтому исключения
        # перечислены по отдельности, а не одной alternation-группой.
        fp_prefixes = ("invalid ", "wrong ", "bad ", "incorrect ")
        fp_lookbehind = "".join(f"(?<!{re.escape(p)})" for p in fp_prefixes)


        patterns = [
            ("JWT", re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*')),
            ("URL", re.compile(r'(?i)\b(?:https?|ftps?|ssh|git|ftp|ws|wss)://[^\s<>"\']+')),
            ("TOKEN", re.compile(
                r'(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}'
                r'|xox[baprs]-[A-Za-z0-9-]{10,}|ya29\.[A-Za-z0-9\-_]+'
                r'|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b'
            )),
            ("CLOUD_SECRET", re.compile(
                r'(?i)\b(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|'
                r'azure[_-]?storage[_-]?key|google[_-]?api[_-]?key|sessiontoken|accountkey|'
                r'clientsecret|oauth_token|access_token|refresh_token)\s*[:=]\s*["\']?'
                r'([A-Za-z0-9/+=_.:-]{8,})'
            )),
            ("SSH_KEY", re.compile(
                r'-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY-----.*?-----END '
                r'(?:OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY-----',
                re.DOTALL,
            )),
            ("CONN_STR", re.compile(
                r'(?i)\b(?:'
                r'mongodb(?:\+srv)?://[^\s"\'<>]+|'
                r'(?:postgres(?:ql)?|mysql|mssql|amqp|redis|oracle|jdbc|snowflake|redshift)://[^\s"\'<>]+|'
                r'(?:Data Source|Server|Host|User Id|Uid|Pwd|Database|Initial Catalog|ConnectionString)\s*=\s*[^;\n\r,\s]+(?:;\s*(?:Data Source|Server|Host|User Id|Uid|Pwd|Database|Initial Catalog|ConnectionString)\s*=\s*[^;\n\r,\s]+)+'
                r')'
            )),
            # Файловые пути сами по себе НЕ маскируются: общий regex на "/"
            # ловит протокольные хвосты (HTTP/1.1, IKEv2/AES256), даты
            # (2026/09/16) и CIDR/порты, оставляя в логе шум вместо
            # контекста. Имя пользователя в домашнем каталоге — отдельно,
            # паттерном USER_PATH ниже.

            ("BASE64_CMD", re.compile(r'(?i)(-(?:e|enc|encodedcommand)\s+)([A-Za-z0-9+/=]{20,2000})')),

            ("CEF_KV", re.compile(rf'(?i)\b({cef_alt})=([^\s,;()\[\]{{}}]{{1,{n}}})')),

            ("SECRET", re.compile(
                rf'(?i){fp_lookbehind}(\b(?:{secret_alt})\b\s*[:=]\s*["\']?)'
                rf'([^\s,;()\[\]{{}}`\'\"]{{1,{n}}})'
            )),

            ("USER_FIELD", re.compile(
                rf'(?i){fp_lookbehind}(\b(?:{user_alt})\b\s*[:=]\s*["\']?)'
                rf'([^\s,;()\[\]{{}}`\'\"]{{1,{n}}})'
            )),

            ("AUTH_USER", re.compile(
                r'(?i)(\b(?:accepted|failed)\s+password\s+for\s+(?:invalid\s+user\s+)?'
                r'|\bsession\s+(?:opened|closed)\s+for\s+user\s+'
                r'|\bfor\s+user\s+["\']'
                r"|'su\s+(?:-\s+)?"
                r"|\bUser\s+'"
                r')([A-Za-z0-9_.-]+)'
            )),

            ("AUTH_USER_CISCO", re.compile(r'(?i)(\bby\s+)([A-Za-z0-9_.-]+)(?=\s+on\s+vty)')),

            ("USER_PATH", re.compile(
                r'(?i)(?:[A-Za-z]:\\Users\\|/home/|/Users/)([A-Za-z0-9._-]+)'
            )),

            ("SID", re.compile(r'\bS-\d-\d+(?:-\d+)+\b')),

            ("HASH", re.compile(r'\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b')),

            ("UUID", re.compile(r'\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b')),

            ("EMAIL", re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),

            ("PHONE", re.compile(rf'(?:{phone_alt})\s*\(?\d{{2,4}}\)?[\s.-]?\d{{3}}[\s.-]?\d{{2}}[\s.-]?\d{{2}}\b')),

            ("FQDN", re.compile(rf'\b(?:[a-zA-Z0-9-]+\.)+(?:{tld_alt})\b', re.IGNORECASE)),

            # Windows DOMAIN\user. Lookbehind (?<![\\]) отсекает сегменты
            # пути вроде Windows\System32 после C:\ — иначе после отказа
            # от generic PATH они маскировались бы как логин.
            ("USER", re.compile(r'(?<![\\])\b[A-Za-z0-9_-]+\\[A-Za-z0-9._-]+\b')),

            ("MAC", re.compile(r'\b(?:[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b')),

            ("IP_NET", re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2}|:\d{1,5})\b'
            )),

            ("IP", re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|'
                r'(?<![0-9a-fA-F:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])'
            )),

            ("ORG", self._build_org_pattern()),
        ]
        custom = []
        for spec in self.config.iter_custom_patterns():
            if not spec.get("enabled", True):
                continue
            regex_text = str(spec.get("pattern") or "")
            if not regex_text:
                continue
            name = str(spec.get("name") or spec.get("type") or "CUSTOM").upper()
            tag = f"CUSTOM:{name}"
            pseudo_type = str(spec.get("type") or tag).upper()
            try:
                compiled = re.compile(regex_text)
            except re.error:
                continue
            self.custom_pattern_metadata[tag] = {
                "name": name,
                "type": tag,
                "strategy": str(spec.get("strategy", "full")).lower(),
                "priority": int(spec.get("priority", 0)),
            }
            custom.append((tag, compiled))
        return custom + patterns

    def _build_org_pattern(self) -> "re.Pattern":
        """Собирает паттерн ORG из org_name и всех org_aliases (см.
        docstring config.py) одной regex-альтернативой. Пустые/дублирующиеся
        варианты отбрасываются; сортировка по убыванию длины гарантирует,
        что более длинный алиас (например, "Bank of Example") не будет
        случайно "перехвачен" совпадением по более короткой подстроке,
        стоящей раньше в альтернативе (важно для чтения диффа/статистики,
        сам факт маскирования при этом не пострадал бы в любом порядке —
        `\\b...\\b` в любом случае покрывает всё вхождение целиком)."""
        names = [self.config.org_name] + list(self.config.org_aliases)
        seen = set()
        unique_names = []
        for name in names:
            name = name.strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                unique_names.append(name)
        if not unique_names:
            # Конфигурация с пустым org_name (config.validate() уже
            # предупредит об этом) — паттерн, заведомо ничего не матчащий.
            return re.compile(r'(?!)')
        unique_names.sort(key=len, reverse=True)
        alternation = "|".join(re.escape(n) for n in unique_names)
        return re.compile(r'\b(?:' + alternation + r')\b', re.IGNORECASE)

    # ------------------------------------------------------------------
    # Классификация и хэширование значений
    # ------------------------------------------------------------------

    def _fqdn_stopwords(self):
        extra = {s.lower() for s in self.config.fqdn_stopwords}
        return set(DEFAULT_FQDN_STOPWORDS) | extra

    def _should_keep_value(self, val: str, tag: str) -> bool:
        return is_allowlisted(val, self.config.allowlist)

    def _classify_value(self, val: str) -> str:
        """Определяет тип "сырого" значения (извлечённого из key=value,
        JSON-поля и т.п.), чтобы хэшировать его с тем же префиксом, что и
        при обнаружении этого же значения в свободном тексте. Кэшируется
        на уровне экземпляра (см. __init__ и docstring модуля, пункт 8)."""
        v = val.strip().strip('"\'')
        if not v:
            return "VALUE"
        cached = self._classify_cache.get(v)
        if cached is not None:
            return cached
        tag = self._classify_value_uncached(v)
        if len(self._classify_cache) >= self._CLASSIFY_CACHE_MAX_SIZE:
            # Простая защита от неограниченного роста на очень больших/
            # разнообразных логах: сбрасываем кэш целиком вместо частичного
            # вытеснения — это не бесплатно, но не требует доп. структур
            # данных (в отличие от LRU) и не влияет на корректность,
            # только на частоту повторных вычислений при таком объёме.
            self._classify_cache.clear()
        self._classify_cache[v] = tag
        return tag

    def _classify_value_uncached(self, v: str) -> str:
        for tag in self.CLASSIFY_ORDER:
            pattern = self.patterns_dict.get(tag)
            if not pattern or not pattern.fullmatch(v):
                continue
            if tag == "IP" and not self._is_valid_ip(v):
                continue
            if tag == "HASH" and not is_plausible_free_text_hash(
                    v, v, 0, len(v), require_context=False):
                continue
            if tag == "FQDN" and not is_plausible_fqdn(v, self._fqdn_stopwords()):
                continue
            if tag == "PHONE" and not is_plausible_phone(v):
                continue
            if tag == "USER" and not is_plausible_windows_user(v):
                continue
            return tag
        return "VALUE"

    def _hash_val(self, val: str, prefix: str) -> str:
        """Возвращает детерминированный псевдоним для значения (HMAC-SHA256
        с PBKDF2-растянутой солью в роли ключа) и регистрирует его в
        таблице соответствия. При коллизии усечённого хэша добавляет
        числовой суффикс, чтобы два разных значения никогда не
        "склеились" под одним псевдонимом.

        Регистр значения нормализуется (lower()) перед хэшированием для
        всех типов, КРОМЕ перечисленных в CASE_SENSITIVE_TYPES (пароли,
        токены и т.п.) — для них регистр является частью самого секрета
        и не должен "схлопываться" (см. docstring модуля, пункт 7)."""
        if self._should_keep_value(val, prefix):
            return val
        self.stats[prefix] += 1

        normalized = val if prefix in self.CASE_SENSITIVE_TYPES else val.lower()
        cache_key = f"{prefix}:{normalized}"
        if cache_key in self._hash_cache:
            return self._hash_cache[cache_key]

        digest = hmac.new(self._hmac_key, normalized.encode('utf-8'), hashlib.sha256).hexdigest()
        h = digest[:self.config.hash_len]
        base_pseudo = f"[{prefix}_{h}]"
        pseudo = base_pseudo
        suffix = 1
        while pseudo in self.reverse_mapping and not _safe_str_eq(self.reverse_mapping[pseudo], val):
            suffix += 1
            pseudo = f"[{prefix}_{h}_{suffix}]"

        self._hash_cache[cache_key] = pseudo
        self.mapping_table[val] = pseudo
        self.reverse_mapping[pseudo] = val
        return pseudo

    def _hash_classified(self, val: str, default_tag: str = "VALUE") -> str:
        """Классифицирует значение по ФОРМАТУ (IP/EMAIL/HASH/...) и
        хэширует его под этим тегом. Если формат не распознан —
        используется default_tag (тип, соответствующий ПОЛЮ, из которого
        значение извлечено — "USER" для USER_FIELD, "SECRET" для SECRET),
        а не generic "VALUE": мы уже знаем из имени ключа/конструкции,
        что это за данные, даже если само значение ("admin", "root",
        "hunter2") не похоже ни на один более специфичный формат."""
        tag = self._classify_value(val)
        if tag == "VALUE":
            tag = default_tag
        return self._hash_val(val, tag)

    # ------------------------------------------------------------------
    # Подстановочные обработчики для отдельных типов паттернов
    # ------------------------------------------------------------------

    def _sub_cef_kv(self, m: "re.Match") -> str:
        field_name, val = m.group(1), m.group(2)
        default_tag = "USER" if field_name.lower() in self._cef_user_fields_lower else "VALUE"
        return f"{field_name}={self._hash_classified(val, default_tag)}"

    def _sub_key_value_generic(self, default_tag: str):
        """Замыкание для SECRET/USER_FIELD: сохраняет неизменным префикс
        (m.group(1) — сама конструкция "user=", "password:" и т.п.),
        заменяет значение (m.group(2)) на псевдоним, классифицированный
        по содержимому с откатом на default_tag (см. _hash_classified)."""
        def _inner(m: "re.Match") -> str:
            return f"{m.group(1)}{self._hash_classified(m.group(2), default_tag)}"
        return _inner

    def _sub_force_tag(self, tag: str):
        """Замыкание для паттернов, где семантика значения ОДНОЗНАЧНО
        известна из самой конструкции совпадения (например, AUTH_USER:
        "Accepted password for X from" не бывает ни о чём, кроме имени
        пользователя) — в отличие от _sub_key_value_generic, тип НЕ
        уточняется по содержимому значения, он всегда фиксирован."""
        def _inner(m: "re.Match") -> str:
            return f"{m.group(1)}{self._hash_val(m.group(2), tag)}"
        return _inner

    def _sub_org(self, m: "re.Match") -> str:
        """Подстановочный обработчик для ORG. При выключенном
        `config.org_aliases_share_pseudonym` (по умолчанию) — обычное
        поведение: каждая буквально совпавшая строка (org_name или
        конкретный org_alias) хэшируется независимо, свой псевдоним на
        каждый вариант написания.

        При включённом флаге — ВСЕ совпадения (независимо от того, каким
        именно алиасом оказалось конкретное вхождение) сходятся к ОДНОМУ
        псевдониму, посчитанному от канонического `config.org_name`:
        первое встреченное упоминание идёт через обычный `_hash_val`
        (регистрирует псевдоним в reverse_mapping, применяет
        суффикс-защиту от коллизий с не связанными значениями); дальше
        просто переиспользуем уже посчитанный псевдоним из кэша, вручную
        учитывая occurrence в статистике (раз мы обходим повторный вызов
        `_hash_val`, который иначе насчитал бы ещё одну PBKDF2-хэш-операцию
        и, что важнее, ещё один инкремент stats — тут инкремент нужен
        ровно один раз за вызов, а не ноль).

        Каждое буквальное вхождение (даже с переиспользованным псевдонимом)
        всё равно регистрируется в `mapping_table` под СВОИМ конкретным
        текстом — это нужно, чтобы подсветка в Input (см. gui.py,
        _highlight_original_values, которая ищет по ключам mapping_table)
        по-прежнему находила каждый алиас отдельно, а не только тот,
        что первым попал в reverse_mapping."""
        matched = m.group(0)
        if not self.config.org_aliases_share_pseudonym:
            return self._hash_val(matched, "ORG")

        canonical = self.config.org_name
        cache_key = f"ORG:{canonical.lower()}"
        if cache_key in self._hash_cache:
            self.stats["ORG"] += 1
            pseudo = self._hash_cache[cache_key]
        else:
            pseudo = self._hash_val(canonical, "ORG")
        self.mapping_table[matched] = pseudo
        return pseudo

    def _sub_base64_cmd(self, m: "re.Match") -> str:
        return f"{m.group(1)}{self._hash_val(m.group(2), 'B64_CMD')}"

    def _sub_user_path(self, m: "re.Match") -> str:
        return m.group(0).replace(m.group(1), self._hash_val(m.group(1), "USER"))

    def _sub_sid(self, m: "re.Match") -> str:
        val = m.group(0)
        if val.upper() in self.well_known_sids:
            return val
        return self._hash_val(val, "SID")

    def _sub_uuid(self, m: "re.Match") -> str:
        val = m.group(0)
        if val.lower() == self.nil_guid:
            return val
        return self._hash_val(val, "UUID")

    def _mask_value(self, value: str, prefix: str, strategy: str = "full") -> str:
        if strategy == "partial":
            if len(value) <= 2:
                return self._hash_val(value, prefix)
            keep = max(1, min(2, len(value) // 4))
            head = value[:keep]
            tail = value[-keep:] if keep else ""
            middle = value[keep:-keep] if keep else value
            if middle:
                return head + self._hash_val(middle, prefix) + tail
            return self._hash_val(value, prefix)
        if strategy == "format":
            mask = []
            for ch in value:
                if ch.isalpha():
                    mask.append("X" if ch.isupper() else "x")
                elif ch.isdigit():
                    mask.append("9")
                else:
                    mask.append(ch)
            return "".join(mask)
        return self._hash_val(value, prefix)

    def _sub_generic(self, prefix: str):
        def _inner(m: "re.Match") -> str:
            return self._hash_val(m.group(0), prefix)
        return _inner

    def _sub_custom(self, meta: Dict[str, Any]):
        strategy = str(meta.get("strategy", "full")).lower()
        prefix = str(meta.get("type") or meta.get("name") or "CUSTOM").upper()

        def _inner(m: "re.Match") -> str:
            return self._mask_value(m.group(0), prefix, strategy)
        return _inner

    @staticmethod
    def _is_valid_ip(candidate: str) -> bool:
        """Настоящая проверка того, что кандидат — валидный IPv4/IPv6-адрес
        (см. комментарий у паттерна IP в _build_patterns: сам regex —
        намеренно широкий "кандидат", допускающий синтаксически похожие,
        но не являющиеся адресом строки вроде таймстампа "12:30:45").
        Используется и в _sub_ip (решение — маскировать или нет), и в
        verify() (иначе gatekeeper ложно ругался бы на обычный таймстамп
        в уже анонимизированном тексте, приняв его за "незамаскированный
        IP")."""
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            return False

    def _sub_ip(self, m: "re.Match") -> str:
        """Подстановочный обработчик для IP. Паттерн IP — намеренно широкий
        "кандидат" (см. комментарий в _build_patterns), особенно для
        IPv6: он допускает совпадения, не являющиеся настоящим IP-адресом
        (например, таймстамп "12:30:45" или MAC-подобная строка без "::"
        и не ровно 8 групп). Настоящая проверка — в _is_valid_ip: если
        совпадение не парсится как валидный IPv4/IPv6, оставляем текст
        БЕЗ ИЗМЕНЕНИЙ (это не адрес, значит и маскировать нечего — и, что
        важнее, не рискуем случайно "спрятать" под generic-псевдонимом
        обычный текст типа времени)."""
        candidate = m.group(0)
        if not self._is_valid_ip(candidate):
            return candidate
        return self._hash_val(candidate, "IP")

    def _sub_hash(self, m: "re.Match") -> str:
        value = m.group(0)
        if not is_plausible_free_text_hash(
                value, m.string, m.start(), m.end(),
                require_context=self.config.hash_require_context):
            return value
        return self._hash_val(value, "HASH")

    def _sub_fqdn(self, m: "re.Match") -> str:
        value = m.group(0)
        if not is_plausible_fqdn(value, self._fqdn_stopwords()):
            return value
        return self._hash_val(value, "FQDN")

    def _sub_phone(self, m: "re.Match") -> str:
        value = m.group(0)
        if not is_plausible_phone(value):
            return value
        return self._hash_val(value, "PHONE")

    def _sub_windows_user(self, m: "re.Match") -> str:
        value = m.group(0)
        if not is_plausible_windows_user(value):
            return value
        return self._hash_val(value, "USER")

    def _mask_structured_token(self, value: str) -> str:
        if not value:
            return value
        return self._hash_classified(value, "VALUE")

    def _dumps_json(self, obj: Any, original: Optional[str] = None) -> str:
        if original and self.config.json_preserve_formatting and "\n" not in original.strip():
            return json.dumps(obj, ensure_ascii=False)
        if original and "\n" in original.strip():
            return json.dumps(obj, ensure_ascii=False, indent=2)
        if not self.config.json_preserve_formatting:
            return json.dumps(obj, ensure_ascii=False, indent=2)
        return json.dumps(obj, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Публичные методы анонимизации
    # ------------------------------------------------------------------

    def _anonymize_text_impl(self, text: str) -> str:
        """Фактическая реализация без защиты от таймаута — вызывается
        через безопасную обёртку `anonymize_text` (см. ниже)."""
        if self.config.multiline_join:
            text = join_continued_lines(text)
        if self.config.parse_structured:
            parts = []
            for line in text.splitlines(keepends=True):
                parts.append(mask_structured_line(line, self._mask_structured_token))
            text = "".join(parts)
        for prefix, pattern in self.patterns:
            if prefix == "CEF_KV":
                text = pattern.sub(self._sub_cef_kv, text)
            elif prefix == "SECRET":
                text = pattern.sub(self._sub_key_value_generic("SECRET"), text)
            elif prefix == "USER_FIELD":
                text = pattern.sub(self._sub_key_value_generic("USER"), text)
            elif prefix in ("AUTH_USER", "AUTH_USER_CISCO"):
                text = pattern.sub(self._sub_force_tag("USER"), text)
            elif prefix == "ORG":
                text = pattern.sub(self._sub_org, text)
            elif prefix == "IP":
                text = pattern.sub(self._sub_ip, text)
            elif prefix == "HASH":
                text = pattern.sub(self._sub_hash, text)
            elif prefix == "FQDN":
                text = pattern.sub(self._sub_fqdn, text)
            elif prefix == "PHONE":
                text = pattern.sub(self._sub_phone, text)
            elif prefix == "USER":
                text = pattern.sub(self._sub_windows_user, text)
            elif prefix == "BASE64_CMD":
                text = pattern.sub(self._sub_base64_cmd, text)
            elif prefix == "USER_PATH":
                text = pattern.sub(self._sub_user_path, text)
            elif prefix == "SID":
                text = pattern.sub(self._sub_sid, text)
            elif prefix == "UUID":
                text = pattern.sub(self._sub_uuid, text)
            elif prefix.startswith("CUSTOM:"):
                text = pattern.sub(self._sub_custom(self.custom_pattern_metadata.get(prefix, {})), text)
            else:
                text = pattern.sub(self._sub_generic(prefix), text)
        return text

    def anonymize_text(self, text: str) -> str:
        """Маскирование произвольного свободного текста (одна или
        несколько строк, без специального разбора JSON).

        Выполняется с таймаутом (`config.regex_timeout_seconds`) как
        базовая защита от ReDoS на специально сконструированном входе.
        При превышении таймаута возвращается явный маркер вместо
        частично замаскированного текста (см. docstring модуля) —
        частичная маскировка потенциально опаснее, чем явный отказ.

        >>> a = SOCLogAnonymizer(salt="x", config=AnonymizerConfig(pbkdf2_iterations=100))
        >>> "@" in a.anonymize_text("contact me at jdoe@example.com")
        False
        """
        if not text:
            return text

        timeout = self.config.regex_timeout_seconds
        if timeout is None:
            return self._anonymize_text_impl(text)

        max_orphaned = self.config.max_orphaned_regex_threads
        with self._orphaned_thread_lock:
            if max_orphaned and self._orphaned_thread_count >= max_orphaned:
                # Лимит "зависших" потоков уже исчерпан (см. docstring
                # модуля, пункт 6) — отказываемся даже пытаться, чтобы не
                # добавить ещё один поток поверх уже накопленных. Это
                # ограничивает рост потребления памяти/потоков процессом
                # при систематической подаче вредоносного входа.
                logger.warning(
                    "Достигнут предел одновременных потоков-таймаутов regex "
                    "(%d) — блок текста длиной %d символов пропущен без "
                    "попытки обработки.", max_orphaned, len(text),
                )
                return _TIMEOUT_MARKER.format(n=len(text))

        result_holder: Dict[str, Any] = {}
        done_event = threading.Event()

        def _worker():
            try:
                result_holder["result"] = self._anonymize_text_impl(text)
            except Exception as exc:  # noqa: BLE001 — пробрасываем через holder
                result_holder["error"] = exc
            finally:
                done_event.set()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            logger.warning(
                "Regex timeout (%.1fs) превышен при анонимизации блока текста длиной %d символов. "
                "Возвращён маркер вместо возможно частично замаскированного текста.",
                timeout, len(text),
            )
            with self._orphaned_thread_lock:
                self._orphaned_thread_count += 1

            def _release_slot():
                # Дожидается фактического завершения зависшего потока (может
                # никогда не завершиться — тогда слот освободится только при
                # завершении процесса, что и так уже было ограничением
                # daemon-потока) и освобождает счётчик, чтобы не занижать
                # лимит для последующих штатных блоков после того, как
                # аномальный блок всё же досчитается.
                done_event.wait()
                with self._orphaned_thread_lock:
                    self._orphaned_thread_count -= 1

            threading.Thread(target=_release_slot, daemon=True).start()
            return _TIMEOUT_MARKER.format(n=len(text))

        if "error" in result_holder:
            raise result_holder["error"]
        return result_holder.get("result", text)

    def anonymize_json(self, data: Union[Dict, List, Any], _key_path: str = "") -> Union[Dict, List, Any]:
        """Рекурсивное маскирование JSON без взлома структуры. Значение
        чувствительного ключа классифицируется по своему формату
        (IP/EMAIL/...), а не хэшируется "вслепую", чтобы то же значение,
        встреченное где-то ещё, получило тот же псевдоним.

        `_key_path` — накопленный "плоский" путь ключей от корня документа
        (тем же способом очищенный от `_`/`.`, что и одиночный ключ, без
        разделителей между уровнями): для `{"subject": {"account":
        {"name": "admin"}}}` путь до листа "name" — "subjectaccountname".
        Это позволяет распознавать чувствительные поля во ВЛОЖЕННЫХ
        структурах (типичных для нормализованных событий SIEM вроде
        MaxPatrol 10 — `subject.account.name`, `object.account.name`), а
        не только там, где чувствительный ключ и есть сам плоский ключ
        документа. Совпадение проверяется и по непосредственному ключу
        (как раньше — для плоских документов вроде Windows Event Log
        JSON, где "SubjectAccountName" уже плоский ключ), и по полному
        накопленному пути — этого достаточно, чтобы один и тот же список
        `sensitive_json_keys`/`key_type_hints` работал для обоих случаев
        без дублирования записей."""
        if isinstance(data, dict):
            new_dict = {}
            for key, val in data.items():
                clean_key = self._normalize_json_key(key)
                full_path = _key_path + clean_key
                matched_key = next(
                    (
                        configured_key
                        for configured_key in self.config.sensitive_json_keys
                        if self._normalize_json_key(configured_key) in (full_path, clean_key)
                    ),
                    None,
                )
                rule = self._match_context_rule(key, full_path)
                if rule and isinstance(val, str) and val:
                    strategy = str(rule.get("strategy") or rule.get("mask") or "full").lower()
                    tag = str(rule.get("type") or rule.get("tag") or rule.get("kind") or "SENSITIVE").upper()
                    new_dict[key] = self._mask_value(val, tag, strategy)
                elif matched_key and isinstance(val, str) and val:
                    tag = self._classify_value(val)
                    if tag == "VALUE":
                        tag = next(
                            (
                                hint
                                for configured_key, hint in self.config.key_type_hints.items()
                                if self._normalize_json_key(configured_key)
                                == self._normalize_json_key(matched_key)
                            ),
                            "SENSITIVE",
                        )
                    new_dict[key] = self._hash_val(val, tag)
                else:
                    new_dict[key] = self.anonymize_json(val, _key_path=full_path)
            return new_dict
        elif isinstance(data, list):
            return [self.anonymize_json(item, _key_path=_key_path) for item in data]
        elif isinstance(data, str):
            return self.anonymize_text(data)
        else:
            return data

    def _try_parse_json(self, text_str: str):
        try:
            return json.loads(text_str)
        except Exception:
            return None

    def anonymize(self, text: str) -> str:
        """Универсальная точка входа. Поддерживает: одиночный JSON-документ
        на весь текст, NDJSON (объект на строку), произвольный текст."""
        text_str = text.strip()
        if not text_str:
            return text

        if (text_str.startswith("{") and text_str.endswith("}")) or \
           (text_str.startswith("[") and text_str.endswith("]")):
            parsed = self._try_parse_json(text_str)
            if parsed is not None:
                anonymized_obj = self.anonymize_json(parsed)
                return self._dumps_json(anonymized_obj, text_str)

        lines = text.splitlines()
        non_empty = [l for l in lines if l.strip()]
        if len(non_empty) > 1 and all(l.strip().startswith(("{", "[")) for l in non_empty):
            out_lines = []
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    out_lines.append(line)
                    continue
                parsed = self._try_parse_json(stripped)
                if parsed is not None:
                    out_lines.append(self._dumps_json(self.anonymize_json(parsed), stripped))
                else:
                    out_lines.append(self.anonymize_text(line))
            return "\n".join(out_lines)

        return self.anonymize_text(text)

    def anonymize_result(self, text: str) -> AnonymizeResult:
        """Like anonymize(), plus stats/mapping/verify in one object."""
        out = self.anonymize(text)
        safe, issues = self.verify(out)
        return AnonymizeResult(
            text=out,
            stats=self.get_stats(),
            mapping=dict(self.mapping_table),
            issues=list(issues),
            safe=safe,
            metrics=self.get_metrics(),
        )

    def anonymize_line(self, line: str) -> str:
        """Анонимизация одной строки — используется для построчного
        стриминга больших файлов без загрузки их целиком в память.
        Если строка сама по себе валидный JSON (типично для NDJSON-логов),
        применяется точная логика по ключам, иначе — текстовые паттерны.
        Переносы строк сохраняются как есть."""
        stripped = line.rstrip("\r\n")
        trailing = line[len(stripped):]
        body = stripped.strip()
        if body.startswith(("{", "[")):
            parsed = self._try_parse_json(body)
            if parsed is not None:
                return self._dumps_json(self.anonymize_json(parsed), body) + trailing
        return self.anonymize_text(stripped) + trailing

    def anonymize_stream(self, lines: Iterable[str]) -> Iterator[str]:
        """Построчный генератор — обрабатывает лог с постоянным объёмом
        памяти независимо от размера файла. Не подходит для случая, когда
        весь файл — это один JSON-документ, растянутый на много строк
        (см. README, раздел "Известные ограничения")."""
        for line in lines:
            yield self.anonymize_line(line)

    def deanonymize(self, text: str) -> str:
        """Обратная де-анонимизация ответа LLM по таблице обратных соответствий."""
        if not text or not self.reverse_mapping:
            return text
        sorted_pseudos = sorted(self.reverse_mapping.keys(), key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(p) for p in sorted_pseudos))
        return pattern.sub(lambda m: self.reverse_mapping[m.group(0)], text)

    @staticmethod
    def _normalize_json_path(path_value: Any) -> str:
        """Normalize JSON path strings to a flat, separator-agnostic form.

        The internally tracked JSON path is always flattened to a single
        string without delimiters, e.g. ``subject.account.name`` becomes
        ``subjectaccountname``. Rules may arrive in either flat or dotted
        (``$.user.token`` / ``user.token`` / ``user[0].token``) form; this
        helper makes both representations comparable.
        """
        if path_value is None:
            return ""
        raw = str(path_value).strip()
        if not raw:
            return ""
        raw = raw.replace("$", "")
        raw = raw.replace("[", ".").replace("]", "")
        raw = raw.replace("/", ".")
        parts = [part for part in re.split(r"[^0-9A-Za-z]+", raw) if part]
        return "".join(parts).casefold()

    def _match_context_rule(self, key_name: str, json_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Return a configured context rule matching a JSON key or JSONPath."""
        if not getattr(self.config, "context_rules", None):
            return None
        normalized_name = self._normalize_json_key(str(key_name or ""))
        candidate_path = str(json_path or "")
        candidate_path_norm = self._normalize_json_path(candidate_path)
        for rule in self.config.context_rules:
            if not isinstance(rule, dict) or not rule.get("enabled", True):
                continue
            field_name = rule.get("field") or rule.get("field_name") or rule.get("name") or rule.get("key")
            if field_name and self._normalize_json_key(str(field_name)) == normalized_name:
                return rule
            json_path_val = rule.get("json_path") or rule.get("jsonPath") or rule.get("path") or rule.get("jsonpath")
            if json_path_val and candidate_path_norm:
                path_norm = self._normalize_json_path(json_path_val)
                if path_norm and (
                    candidate_path_norm == path_norm
                    or candidate_path_norm.endswith(path_norm)
                    or path_norm.endswith(candidate_path_norm)
                ):
                    return rule
            field_pattern = rule.get("field_pattern") or rule.get("fieldPattern") or rule.get("match")
            if field_pattern and re.search(field_pattern, str(key_name or ""), re.IGNORECASE):
                return rule
        return None

    def find_matches(self, text: str) -> List[Dict[str, Any]]:
        """Return raw matched values and their types for a text block."""
        matches: List[Dict[str, Any]] = []
        for tag, pattern in self.patterns:
            if tag.startswith("CUSTOM:"):
                meta = self.custom_pattern_metadata.get(tag, {})
                if meta.get("strategy") == "format":
                    # format-preserving masks keep the original value only for report purposes.
                    pass
            for match in pattern.finditer(text):
                value = match.group(0)
                if tag == "IP" and not self._is_valid_ip(value):
                    continue
                if tag == "UUID" and value.lower() == self.nil_guid:
                    continue
                if tag == "SID" and value.upper() in self.well_known_sids:
                    continue
                if is_allowlisted(value, self.config.allowlist):
                    continue
                if tag == "HASH" and not is_plausible_free_text_hash(
                        value, text, match.start(), match.end(),
                        require_context=self.config.hash_require_context):
                    continue
                if tag == "FQDN" and not is_plausible_fqdn(value, self._fqdn_stopwords()):
                    continue
                if tag == "PHONE" and not is_plausible_phone(value):
                    continue
                if tag == "USER" and not is_plausible_windows_user(value):
                    continue
                matches.append({
                    "type": tag, "value": value,
                    "start": match.start(), "end": match.end(),
                    "line": text.count("\n", 0, match.start()) + 1,
                })
        return matches

    def get_quality_report(self, text: str) -> Dict[str, Any]:
        """Summarize found values, counts, and verification issues for a block."""
        findings = self.find_matches(text)
        by_type: Dict[str, int] = {}
        for item in findings:
            by_type[item["type"]] = by_type.get(item["type"], 0) + 1
        safe, issues = self.verify(text)
        return {
            "safe": safe,
            "issues": issues,
            "missed": issues,
            "found": findings,
            "total_found": len(findings),
            "by_type": by_type,
        }

    quality_report = get_quality_report

    def verify(self, text: str) -> Tuple[bool, List[str]]:
        """Gatekeeper-проверка: прогоняет ВСЕ generic-паттерны заново по
        итоговому тексту, чтобы поймать любые типы незамаскированных
        данных, пропущенные основным проходом. Well-known SID и nil GUID
        не считаются утечкой, т.к. маскируются намеренно."""
        issues = []
        for tag, pattern in self.patterns:
            if tag in ("CEF_KV", "SECRET", "USER_FIELD", "USER_PATH", "BASE64_CMD",
                       "AUTH_USER", "AUTH_USER_CISCO") or tag.startswith("CUSTOM:"):
                continue

            def _leftovers():
                for match in pattern.finditer(text):
                    value = match.group(0)
                    if is_allowlisted(value, self.config.allowlist):
                        continue
                    if tag == "IP" and not self._is_valid_ip(value):
                        continue
                    if tag == "UUID" and value.lower() == self.nil_guid:
                        continue
                    if tag == "SID" and value.upper() in self.well_known_sids:
                        continue
                    if tag == "HASH" and not is_plausible_free_text_hash(
                            value, text, match.start(), match.end(),
                            require_context=self.config.hash_require_context):
                        continue
                    if tag == "FQDN" and not is_plausible_fqdn(value, self._fqdn_stopwords()):
                        continue
                    if tag == "PHONE" and not is_plausible_phone(value):
                        continue
                    if tag == "USER" and not is_plausible_windows_user(value):
                        continue
                    yield value

            leftovers = list(_leftovers())
            if not leftovers:
                continue
            if tag == "ORG":
                issues.append("Обнаружено наименование организации")
            else:
                issues.append(f"Обнаружены незамаскированные данные типа {tag}")
        return len(issues) == 0, issues

    # ------------------------------------------------------------------
    # Статистика
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """Возвращает количество замен по типам данных (число вхождений,
        не уникальных значений) — полезно для отчётности о том, что
        именно ушло во внешний сервис."""
        return dict(self.stats)

    def get_metrics(self) -> Dict[str, int]:
        """Return lightweight processing/cache metrics for reports."""
        return {
            "unique_values": len(self.mapping_table),
            "hash_cache_entries": len(self._hash_cache),
            "classification_cache_entries": len(self._classify_cache),
            "replacement_occurrences": sum(self.stats.values()),
        }

    def reset_stats(self) -> None:
        self.stats.clear()

    # ------------------------------------------------------------------
    # Сохранение / загрузка таблицы соответствия
    # ------------------------------------------------------------------

    def save_mapping(self, path: str) -> None:
        """Сохраняет соль и таблицу соответствия в JSON с правами доступа
        0600 (только владелец, на POSIX-системах). Этот файл — по сути,
        ключ деанонимизации: обращайтесь с ним так же, как с исходным
        логом. Нужен, чтобы деанонимизировать ответ LLM в НОВОМ процессе
        (например, при использовании CLI, где каждый запуск — отдельный
        процесс и таблица в памяти не сохраняется)."""
        payload = {
            "schema_version": MAPPING_SCHEMA_VERSION,
            "algorithm": "HMAC-SHA256/PBKDF2",
            "algorithm_version": 1,
            "salt": self.salt,
            "mapping": self.mapping_table,
        }
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write("\n")
        logger.info("Таблица соответствия сохранена: %s (%d значений)", path, len(self.mapping_table))

    @classmethod
    def load_mapping(cls, path: str, config: Optional[AnonymizerConfig] = None) -> "SOCLogAnonymizer":
        """Восстанавливает анонимизатор (соль + таблица соответствия) из
        файла, сохранённого save_mapping(), — для деанонимизации в новом
        процессе/сессии."""
        warning = check_world_readable(path)
        if warning:
            logger.warning("%s", warning)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        version = data.get("schema_version", 0)
        if version > MAPPING_SCHEMA_VERSION:
            logger.warning(
                "mapping-файл %s создан более новой версией инструмента "
                "(schema_version=%s > %s поддерживаемой этой версией) — "
                "возможна неполная совместимость.", path, version, MAPPING_SCHEMA_VERSION,
            )

        inst = cls(salt=data.get("salt"), config=config)
        inst.mapping_table = dict(data.get("mapping", {}))
        inst.reverse_mapping = {v: k for k, v in inst.mapping_table.items()}
        return inst

    # ------------------------------------------------------------------
    # Параллельная обработка (для больших файлов)
    # ------------------------------------------------------------------

    def anonymize_parallel_lines(self, lines: List[str], workers: int = 4,
                                  chunk_size: int = 2000) -> List[str]:
        """Разбивает список строк на чанки и анонимизирует их параллельно
        через ProcessPoolExecutor (regex — CPU-bound задача).

        Консистентность псевдонимов между процессами сохраняется, т.к.
        хэш — чистая функция от (HMAC-ключ, значение): одни и те же
        salt/pbkdf2_iterations + значение в любом процессе дают один и
        тот же псевдоним. Однако разрешение коллизий хэша (суффикс _2,
        _3...) работает независимо в каждом воркере — при реальной
        коллизии (крайне маловероятной при 12-символьном HMAC) в разных
        чанках возможны разные суффиксы. mapping_table и stats этого
        экземпляра пополняются результатами всех воркеров."""
        if workers <= 1 or len(lines) <= chunk_size:
            return [self.anonymize_line(l) for l in lines]

        chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
        # Передаём уже выведенный HMAC-ключ (self._hmac_key), а не только
        # соль — PBKDF2 уже был прогнан один раз здесь, в родительском
        # процессе; без этого КАЖДЫЙ воркер заново прогонял бы 600 000
        # итераций ради того же самого ключа (см. docstring __init__,
        # параметр _prederived_key). bytes — picklable, передаётся между
        # процессами без проблем.
        args = [(self.config.as_dict(), self.salt, self._hmac_key, chunk) for chunk in chunks]

        results: List[str] = []
        with ProcessPoolExecutor(max_workers=workers) as executor:
            for out_lines, mapping, stats in executor.map(_parallel_worker, args):
                results.extend(out_lines)
                self.mapping_table.update(mapping)
                for orig, pseudo in mapping.items():
                    self.reverse_mapping[pseudo] = orig
                self.stats.update(stats)
        return results


def _parallel_worker(args: Tuple[Dict, str, bytes, List[str]]) -> Tuple[List[str], Dict[str, str], Dict[str, int]]:
    """Функция верхнего уровня модуля (обязательное требование
    ProcessPoolExecutor — объект должен быть picklable). Создаёт свой
    экземпляр анонимизатора с той же солью/конфигурацией и обрабатывает
    выделенный ему чанк строк. Ключ передан уже выведенным из родительского
    процесса (см. anonymize_parallel_lines) — PBKDF2 здесь НЕ повторяется."""
    config_dict, salt, hmac_key, chunk = args
    config = AnonymizerConfig(**config_dict)
    local = SOCLogAnonymizer(salt=salt, config=config, _prederived_key=hmac_key)
    out = [local.anonymize_line(line) for line in chunk]
    return out, local.mapping_table, dict(local.stats)
