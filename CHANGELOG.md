# Changelog

## Unreleased

## 2.5.0

- PII ориентированные на РБ: УНП (контрольная сумма), личный номер,
  IBAN BY (mod-97), PAN (Luhn); префиксы телефонов по умолчанию `+375` /
  `80xx` и TLD `.by`.
- Конфиг `mask_strategies` (по умолчанию partial для PHONE/PAN/IBAN/BY_ID).
- Residual-скан в `verify()` / `get_quality_report()` для остатков сверх
  тех же regex, что использовались при маскировании (полезно с
  `--fail-on-unsafe`).
- Кавычки в `key="value with spaces"` / `key='…'` для USER_FIELD и SECRET.
- AUTH: `Invalid user`, `authentication failure for`, `sudo: user :`,
  Windows `Account Name:`.
- `packaging/default_config.json` заточен под Windows EXE-развёртывания в РБ.
- Золотой корпус + `tests/test_quality_v25.py`.
- Ключи таксономии MaxPatrol 10 / PT SIEM в дефолтах (`event_src.host`,
  `subject.account.*`, `recv_ipv4`, assets, MAC/email/phone на
  subject/object); пример `examples/maxpatrol10_event.json`.
- GUI: убран отдельный редактор Allowlist; исключения только в основном
  JSON-конфиге (`"allowlist"`), который также принимает текстовый блок
  (переносы и/или запятые) помимо массива строк.
- GUI: «Очистить всё» на главной панели инструментов; убрано из меню «Ещё».
- GUI: всплывающие подсказки на кнопках главной панели (с горячими
  клавишами, где есть).
- Windows GUI exe: больше не мигает консольное окно при обновлении ACL
  черновика (`icacls` запускается с `CREATE_NO_WINDOW`).

## 2.4.0

- Расширен золотой корпус: Fortinet / Palo Alto / инициатор su / Azure /
  AWS / Windows Event JSON; добавлены тесты оценки FP/FN.
- AUTH-паттерны: инициатор su (`'su root' failed for X on`), Fortinet
  quoted user/login, Palo Alto `from user` / `User … failed`.
- Дефолтные JSON-ключи/подсказки для Azure AD, AWS CloudTrail, Windows Event.
- Детерминированное слияние суффиксов коллизий после `--workers` /
  `batch --workers`.
- `--stream` накапливает pretty-printed многострочные JSON-документы.
- Опциональное шифрование mapping: `--mapping-passphrase` / `--mapping-dpapi`.
- GUI разбит на mixin-модули (`gui_*_mixin.py`); `gui.py` — тонкая оболочка.
- Extras `pip install -e ".[dev]"`; CI lint/typecheck по всему пакету;
  benchmark job; workflow’ы GitHub Release и публикации на PyPI.
- README сокращён; полный справочник перенесён в `docs/REFERENCE.md`.

## 2.3.0

- Упаковка Windows EXE: **onefile** GUI+CLI (основной вариант), опциональный
  onedir, PE version/icon, DPI hook, бандл дефолтного конфига,
  `build_windows.bat`, артефакты Windows CI.
- GUI: crash-лог + MessageBox для windowed-сборок, пути AppData/portable,
  переключатель автосохранения черновика, открытие папок приложения/
  данных/ошибок, превью+sidecar для больших файлов по умолчанию.
- Безопасность: Windows ACL (`icacls`) для соли/mapping/черновиков;
  документация `docs/WINDOWS_EXE.md`.
- Исправлен краш Windows CLI (`UnicodeEncodeError`) при выводе кириллицы
  на консолях cp1252 (также CI на `windows-latest`).
- Исправлена ложная подсветка allowlist-токенов в GUI (например,
  `administrator`), когда более короткое значение вроде `admin` было
  подстрокой.
- Компактная шапка GUI в одну строку панели; вторичные действия — в «Ещё»,
  тема/шрифт/синхронный скролл — в «Вид».
- `org_name` только в конфиге (поле на панели убрано); «Скопировать
  результат» — на главной панели.
- GUI разделён на модули `gui_constants`, `gui_layout`, `gui_profiles`,
  `gui_diff_html`.
- Добавлен списочный редактор allowlist на вкладке «Конфигурация»
  (без source-профилей).
- Убраны session-поля GUI `mask_types` / `skip_types` / `allowlist`;
  `allowlist` остаётся только в конфиге.
- Опции конфигурации `mask_types` и `skip_types` удалены полностью.

## 2.2.0

- Убрано общее маскирование PATH; слэши в протоколах/датах/шифрах
  остаются нетронутыми.
- Добавлены `mask_types`, `skip_types`, `allowlist`, более строгие фильтры
  HASH/FQDN/PHONE/USER, сохранение компактного JSON, склейка многострочных
  продолжений, разбор RFC5424 host и `anonymize_result()`.
- GUI: превью Scan, session-поля mask/skip/allowlist, фильтр типов в
  таблице соответствия и переход к значению, sidecar-вывод для больших
  файлов; константы темы вынесены в `gui_theme.py`.
- Документация: шпаргалка аналитика, каталог ложных срабатываний,
  руководство по своим regex; тесты золотого корпуса.
- Прекращено маскирование путей файловой системы как `PATH`. Старый
  regex «любой `/`» воспринимал версии протоколов, даты и cipher suites
  (`HTTP/1.1`, `2026/09/16`, `IKEv2/AES256`) как пути. Имена
  пользователей в домашних каталогах (`C:\Users\jdoe`, `/home/jdoe`,
  `/Users/jdoe`) по-прежнему маскируются как `USER`.
- Отчёты scan в форматах JSONL, JSON и CSV: размер файла, счётчики
  замен, число строк, позиции изменённых строк, статус безопасности,
  тайминг и метрики кэша.
- `batch --dry-run` и опциональные JSON-события прогресса.
- `diff-config` и `validate-config --fix`.
- Opt-in пользовательские regex-паттерны/типы в конфигурации.
- GUI: упорядочивание/удаление файлов, импорт папки, отмена.
- Предупреждения о повреждённой кодировке и проверки документации/примеров.

## 2.1.0

- Стабильная анонимизация, стриминг, совместимость mapping, GUI и CLI.
