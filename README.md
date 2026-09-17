# 🛡️ SOC Log Anonymizer

[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen)](docs/REFERENCE.md#features)
[![Version](https://img.shields.io/badge/version-2.5.0-informational)](soc_log_anonymizer/__init__.py)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](docs/REFERENCE.md#installation)

Инструмент для SOC-аналитиков: маскирует чувствительные данные в логах
(IP, логины, email, хэши, SID, GUID, MAC, JWT, УНП/PAN/IBAN, секреты и т.д.)
перед отправкой во внешнюю LLM и восстанавливает исходные значения в ответе.

**Только стандартная библиотека Python** — без внешних зависимостей.
Доступен как GUI (tkinter), CLI и Python-библиотека.

## Документация

| Документ | Содержание |
|---|---|
| [Runbook аналитика](docs/RUNBOOK.md) | Порядок работы GUI/CLI, salt/mapping, чеклист перед LLM |
| [Полный справочник](docs/REFERENCE.md) | Конфиг, флаги CLI, безопасность, ограничения, структура |
| [Шпаргалка аналитика](docs/CHEATSHEET.md) | Быстрые рецепты |
| [Ложные срабатывания](docs/FALSE_POSITIVES.md) | Каталог FP/FN |
| [Свои regex](docs/CUSTOM_PATTERNS.md) | Пользовательские паттерны |
| [Windows EXE](docs/WINDOWS_EXE.md) | Сборка и установка |
| [Релизы и PyPI](docs/PUBLISHING.md) | GitHub Releases, подпись, публикация |
| [Шифрование mapping](docs/MAPPING_ENCRYPTION.md) | Парольная фраза / DPAPI |

## Установка

```bash
pip install soc-log-anonymizer
# или из исходников:
pip install -e .
# инструменты разработки:
pip install -e ".[dev]"
```

Windows EXE: см. [docs/WINDOWS_EXE.md](docs/WINDOWS_EXE.md) и GitHub Releases.

## Быстрый старт

```bash
# CLI
python -m soc_log_anonymizer anonymize -i raw.log -o clean.log \
  --org bank --salt-file salt.txt --save-mapping mapping.json --stats

# Деанонимизация ответа LLM
python -m soc_log_anonymizer deanonymize -i reply.txt -o restored.txt \
  --mapping mapping.json

# GUI
python -m soc_log_anonymizer.gui
```

```python
from soc_log_anonymizer import SOCLogAnonymizer, AnonymizerConfig

with SOCLogAnonymizer(salt="...", org_name="bank") as anon:
    clean = anon.anonymize(open("raw.log", encoding="utf-8").read())
    safe, issues = anon.verify(clean)
```

## Возможности (кратко)

- Консистентная HMAC-SHA256/PBKDF2 псевдонимизация IP/USER/EMAIL/HASH/JWT/…
- Syslog, Cisco ASA/IOS, Checkpoint, Fortinet, Palo Alto, Azure/AWS, MaxPatrol 10
- Идентификаторы РБ: УНП, личный номер, IBAN `BY…`, PAN (Luhn); телефоны `+375`/`80xx`
- JSON/NDJSON (в т.ч. pretty-printed в `--stream`), gzip, `.evtx` (Windows/`wevtutil`), batch, `--workers`
- Gatekeeper `verify()` с residual-сканом, аудит-лог, опциональное шифрование mapping
- GUI: подсветка замен, HTML-отчёт, тёмная тема, автосохранение, Windows ACL, DnD файлов

Подробности — в [docs/REFERENCE.md](docs/REFERENCE.md).

## Тесты

```bash
python -m unittest discover -s tests -v
# или после pip install -e ".[dev]":
ruff check soc_log_anonymizer
mypy --ignore-missing-imports soc_log_anonymizer
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
