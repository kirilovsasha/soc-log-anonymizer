"""
CLI для SOC Log Anonymizer — для встраивания в пайплайны/автоматизацию
без GUI. Только стандартная библиотека (argparse, logging, os, sys,
difflib, glob, concurrent.futures).

Переменные окружения (используются как значения по умолчанию, если
соответствующий флаг не передан явно):

    SOC_ANON_SALT_FILE   — путь к файлу с солью (аналог --salt-file)
    SOC_ANON_CONFIG       — путь к файлу конфигурации (аналог --config)

Коды возврата:

    0 — успех, gatekeeper (verify()) не нашёл проблем
    1 — ошибка выполнения (файл не найден, некорректный конфиг и т.п.)
    2 — успех, но gatekeeper нашёл потенциально незамаскированные данные
        И передан флаг --fail-on-unsafe (иначе такой случай -> код 0
        с предупреждением в лог, чтобы не ломать существующие пайплайны
        по умолчанию)

Примеры:

    # Анонимизация файла, соль — из файла (рекомендуется, не в аргументе)
    python -m soc_log_anonymizer anonymize -i raw.log -o clean.log \\
        --org bank --salt-file salt.txt --save-mapping mapping.json --stats

    # Несколько файлов сразу (glob), без -i/-o
    python -m soc_log_anonymizer anonymize logs/*.log --output-dir clean/ \\
        --salt-file salt.txt

    # Большой файл, построчный стриминг + параллельная обработка
    python -m soc_log_anonymizer anonymize -i huge.log -o clean.log --stream --workers 4

    # Архивированный лог (.gz распознаётся автоматически по заголовку,
    # необязательно должно быть именно расширение .gz) — работает и
    # с --stream, и в обычном режиме, без ручной распаковки
    python -m soc_log_anonymizer anonymize -i app.log.gz -o clean.log --salt-file salt.txt

    # Деанонимизация ответа LLM по сохранённой таблице
    python -m soc_log_anonymizer deanonymize -i llm_response.txt -o restored.txt \\
        --mapping mapping.json

    # Пакетная анонимизация каталога логов с единой (консистентной) солью
    python -m soc_log_anonymizer batch --input-dir ./logs --output-dir ./clean_logs \\
        --salt-file salt.txt --save-mapping mapping.json --workers 4

    # Проверка конфигурации перед использованием
    python -m soc_log_anonymizer validate-config myconfig.json

    # Подробный лог хода выполнения в файл (ротация 5 МБ x 3)
    python -m soc_log_anonymizer anonymize -i raw.log -v --log-file run.log ...
"""

import argparse
import atexit
import cProfile
import csv
import difflib
import fnmatch
import glob
import io as _io
import json
import logging
import os
import pstats
import signal
import sys
import time
import tracemalloc
from logging.handlers import RotatingFileHandler
from typing import List, Optional

from . import __version__
from .anonymizer import SOCLogAnonymizer
from .audit import log_audit_event
from .config import AnonymizerConfig, find_default_config_path
from .io_utils import (
    atomic_write_text,
    check_world_readable,
    format_size_mb,
    is_gzip_file,
    iter_log_lines,
    read_file_auto_encoding,
    read_log_file,
    restrict_sensitive_file,
)
from .parallel_merge import (
    apply_pseudo_rewrite,
    build_pseudo_rewrite,
    install_merged_mapping,
    merge_mappings_deterministic,
)

logger = logging.getLogger("soc_log_anonymizer")

ENV_SALT_FILE = "SOC_ANON_SALT_FILE"
ENV_CONFIG = "SOC_ANON_CONFIG"
ENV_ORG = "SOC_ANON_ORG"
ENV_REPORT_FORMAT = "SOC_ANON_REPORT_FORMAT"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNSAFE = 2


def _mapping_crypto_kwargs(args: argparse.Namespace) -> dict:
    passphrase = getattr(args, "mapping_passphrase", None)
    if getattr(args, "mapping_passphrase_env", None):
        passphrase = os.environ.get(args.mapping_passphrase_env) or passphrase
    return {
        "passphrase": passphrase,
        "use_dpapi": bool(getattr(args, "mapping_dpapi", False)),
    }


def _add_mapping_crypto_args(parser: argparse.ArgumentParser, *, for_load: bool = False) -> None:
    parser.add_argument(
        "--mapping-passphrase",
        help="Passphrase for encrypting/decrypting the mapping file",
    )
    parser.add_argument(
        "--mapping-passphrase-env",
        help="Read mapping passphrase from this environment variable",
    )
    if not for_load:
        parser.add_argument(
            "--mapping-dpapi",
            action="store_true",
            help="Encrypt mapping with Windows DPAPI (Windows only)",
        )


def _save_mapping_from_args(anonymizer: SOCLogAnonymizer, args: argparse.Namespace) -> None:
    if not getattr(args, "save_mapping", None):
        return
    anonymizer.save_mapping(args.save_mapping, **_mapping_crypto_kwargs(args))


def _configure_stdio() -> None:
    """Force UTF-8 on stdout/stderr so Cyrillic CLI messages work on Windows.

    GitHub windows-latest (and many Western locales) use cp1252; printing
    Russian text then raises UnicodeEncodeError and aborts the command.
    """
    for stream in (sys.stdout, sys.stderr):
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError, AttributeError):
            pass


class _Progress:
    """Emit stable progress records without contaminating command output."""

    def __init__(self, total: int, args) -> None:
        self.total = total
        self.args = args
        self.started = time.perf_counter()
        self.completed = 0

    def update(self, item: str = "") -> None:
        self.completed += 1
        elapsed = max(time.perf_counter() - self.started, 1e-9)
        rate = self.completed / elapsed
        remaining = max(self.total - self.completed, 0)
        payload = {
            # Keep the original event name for consumers introduced with
            # --progress-events; the additional fields are backwards-compatible.
            "event": "file_complete",
            "completed": self.completed,
            "total": self.total,
            "percent": round(self.completed * 100 / self.total, 2) if self.total else 100.0,
            "elapsed_seconds": round(elapsed, 3),
            "rate_files_per_second": round(rate, 3),
            "eta_seconds": round(remaining / rate, 3) if rate else None,
        }
        if item:
            payload["file"] = item
        if getattr(self.args, "progress_events", False):
            print(json.dumps(payload, ensure_ascii=False), file=sys.stderr, flush=True)
        elif getattr(self.args, "progress", False):
            print("Прогресс: {completed}/{total} ({percent:.1f}%), "
                  "скорость {rate:.2f} файл/с, ETA {eta}".format(
                      completed=self.completed, total=self.total,
                      percent=payload["percent"], rate=rate,
                      eta=("—" if payload["eta_seconds"] is None else
                           f"{payload['eta_seconds']:.1f} с")),
                  file=sys.stderr, flush=True)

    def finish(self) -> None:
        # Completion is represented by the final file_complete event.  Avoid
        # an extra record so existing JSONL consumers keep one event per file.
        return


# ----------------------------------------------------------------------
# Сигналы завершения
# ----------------------------------------------------------------------

def _install_signal_handlers() -> None:
    """Перехватывает SIGINT/SIGTERM для корректного завершения: по
    умолчанию SIGTERM обрывает процесс немедленно, не давая atexit-
    обработчикам (см. _register_atexit_cleanup) отработать и очистить
    чувствительные данные из памяти. sys.exit() внутри обработчика
    поднимает SystemExit, что штатно проходит через atexit."""
    def _handler(signum, _frame):
        name = signal.Signals(signum).name
        logger.warning("Получен сигнал %s, завершение работы...", name)
        sys.exit(130 if signum == signal.SIGINT else 143)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError, AttributeError):
            # ValueError: не в главном потоке; на некоторых платформах
            # (Windows) SIGTERM недоступен — тогда просто пропускаем.
            pass


def _register_atexit_cleanup(anonymizer: SOCLogAnonymizer) -> None:
    """Дополнительная страховка поверх обычного завершения функции:
    гарантирует явную очистку mapping_table/reverse_mapping из памяти
    даже при необработанном исключении или сигнале завершения."""
    atexit.register(anonymizer.clear_sensitive_data)


def _output_path_for(source_path: str, rel_path: str, output_dir: str) -> str:
    """Строит путь выходного файла для batch/multi-file режимов. Если
    исходный файл был gzip-архивом, суффикс `.gz` убирается — результат
    anonymize() всегда обычный текст (мы не сжимаем вывод), и оставлять
    `.gz` в имени было бы вводящим в заблуждение (файл выглядел бы как
    архив, но им не является)."""
    if is_gzip_file(source_path) and rel_path.endswith(".gz"):
        rel_path = rel_path[:-len(".gz")]
    return os.path.join(output_dir, rel_path)


# ----------------------------------------------------------------------
# Профилирование (опционально, только по явному флагу)
# ----------------------------------------------------------------------

def _run_with_profiling(func, args_ns, *call_args, **call_kwargs):
    """Оборачивает вызов func(*call_args) профилировщиками cProfile
    (--profile) и/или tracemalloc (--profile-memory), если запрошено."""
    profile_cpu = getattr(args_ns, "profile", False)
    profile_mem = getattr(args_ns, "profile_memory", False)

    profiler = None
    if profile_cpu:
        profiler = cProfile.Profile()
        profiler.enable()
    if profile_mem:
        tracemalloc.start()

    try:
        return func(*call_args, **call_kwargs)
    finally:
        if profile_cpu and profiler is not None:
            profiler.disable()
            stream = _io.StringIO()
            pstats.Stats(profiler, stream=stream).sort_stats("cumulative").print_stats(20)
            logger.info("Профиль CPU (top-20 по cumulative time):\n%s", stream.getvalue())
        if profile_mem:
            current, peak = tracemalloc.get_traced_memory()
            logger.info("Память: текущая=%.2f МБ, пик=%.2f МБ",
                        format_size_mb(current), format_size_mb(peak))
            tracemalloc.stop()


# ----------------------------------------------------------------------
# Логирование
# ----------------------------------------------------------------------

def _configure_logging(verbosity: int, log_file: Optional[str]) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    root = logging.getLogger("soc_log_anonymizer")
    root.setLevel(level)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root.addHandler(console)

    if log_file:
        # Ротация: 5 файлов по 5 МБ — журналируются только метаданные
        # операций (какой файл, сколько замен), НЕ содержимое логов.
        file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(file_handler)


# ----------------------------------------------------------------------
# Вспомогательные функции
# ----------------------------------------------------------------------

class StrictPermsError(Exception):
    """Поднимается _read_salt/cmd_deanonymize, когда --strict-perms задан
    и соответствующий файл (соль/mapping) доступен на чтение другим
    пользователям системы — вызывающий код превращает это в EXIT_ERROR
    вместо просто предупреждения в лог."""


def _read_salt(args: argparse.Namespace) -> Optional[str]:
    salt_file = args.salt_file or os.environ.get(ENV_SALT_FILE)
    if salt_file:
        warning = check_world_readable(salt_file)
        if warning:
            if getattr(args, "strict_perms", False):
                raise StrictPermsError(warning)
            logger.warning("%s", warning)
        with open(salt_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    if args.salt:
        logger.warning(
            "Передача соли через аргумент командной строки может попасть в историю "
            "shell/список процессов. Предпочтительно использовать --salt-file или %s.",
            ENV_SALT_FILE,
        )
        return args.salt
    return None


def _check_input_size(file_path: str, config: AnonymizerConfig) -> None:
    """Предупреждает (не блокирует), если файл, который будет загружен
    ЦЕЛИКОМ в память (не через --stream), превышает разумный порог."""
    try:
        size_mb = format_size_mb(os.path.getsize(file_path))
    except OSError:
        return
    if size_mb > config.max_input_size_mb:
        logger.warning(
            "Файл %s (%.1f МБ) превышает порог max_input_size_mb=%d — "
            "он будет загружен в память целиком. Для больших файлов "
            "используйте флаг --stream.", file_path, size_mb, config.max_input_size_mb,
        )


def _resolve_config_path(args: argparse.Namespace) -> Optional[str]:
    explicit = getattr(args, "config", None) or os.environ.get(ENV_CONFIG)
    if explicit:
        return explicit
    # Автопоиск рядом с приложением (см. find_default_config_path) —
    # только когда конфиг НЕ указан явно ни через --config, ни через
    # переменную окружения: явное всегда важнее автоматического.
    auto = find_default_config_path()
    if auto:
        logger.info("Автоматически найден и используется конфиг: %s", auto)
    return auto


def _save_salt_if_requested(args: argparse.Namespace, anonymizer: SOCLogAnonymizer) -> None:
    if getattr(args, "save_salt", None):
        fd = os.open(args.save_salt, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(anonymizer.salt)
        warning = restrict_sensitive_file(args.save_salt)
        if warning:
            logger.warning("%s", warning)
        logger.info("Соль сохранена в %s (права ограничены владельцем)", args.save_salt)


def _log_stats(anonymizer: SOCLogAnonymizer) -> None:
    stats = anonymizer.get_stats()
    if not stats:
        logger.info("Статистика: замен не было.")
        return
    parts = ", ".join(f"{tag}={count}" for tag, count in sorted(stats.items(), key=lambda kv: -kv[1]))
    logger.info("Статистика замен: %s | уникальных значений: %d", parts, len(anonymizer.mapping_table))


def _print_diff(original: str, cleaned: str, label: str = "log") -> None:
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        cleaned.splitlines(keepends=True),
        fromfile=f"{label} (original)",
        tofile=f"{label} (anonymized)",
    )
    sys.stderr.writelines(diff)


def _report_verify(anonymizer: SOCLogAnonymizer, cleaned_text: str, fail_on_unsafe: bool) -> int:
    is_safe, issues = anonymizer.verify(cleaned_text)
    if is_safe:
        return EXIT_OK


    for issue in issues:
        logger.warning("Gatekeeper: %s", issue)
    if fail_on_unsafe:
        logger.error("Обнаружены незамаскированные данные, --fail-on-unsafe -> код возврата %d", EXIT_UNSAFE)
        return EXIT_UNSAFE
    return EXIT_OK


def _emit_reports(reports, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(reports, ensure_ascii=False, indent=2))
    elif fmt == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=["input", "size_bytes",
                            "replacements", "unique_values", "stats_by_type",
                            "safe", "issues", "line_count", "elapsed_ms",
                            "metrics"], extrasaction="ignore")
        writer.writeheader()
        for item in reports:
            writer.writerow(dict(item, stats_by_type=json.dumps(item["stats_by_type"],
                         ensure_ascii=False), issues="; ".join(item["issues"]),
                         metrics=json.dumps(item.get("metrics", {}), ensure_ascii=False)))
    else:
        for item in reports:
            print(json.dumps(item, ensure_ascii=False))


def _load_config_for_command(args: argparse.Namespace) -> AnonymizerConfig:
    """Load and optionally enforce configuration validation."""
    config = AnonymizerConfig.load(_resolve_config_path(args))
    issues = config.validate()
    for issue in issues:
        logger.warning("Проблема конфигурации: %s", issue)
    if issues and getattr(args, "strict_config", False):
        raise ValueError("Конфигурация не прошла строгую проверку")
    return config


# ----------------------------------------------------------------------
# anonymize
# ----------------------------------------------------------------------

def cmd_anonymize(args: argparse.Namespace) -> int:
    config = _load_config_for_command(args)

    try:
        salt = _read_salt(args)
    except StrictPermsError as e:
        logger.error("%s", e)
        return EXIT_ERROR
    anonymizer = SOCLogAnonymizer(salt=salt, org_name=args.org, config=config)
    _register_atexit_cleanup(anonymizer)
    _save_salt_if_requested(args, anonymizer)

    if getattr(args, "workers", 1) and args.workers > 1 and not getattr(args, "stream", False):
        logger.warning(
            "--workers без --stream игнорируется для одного файла в памяти. "
            "Параллель по строкам: anonymize --stream --workers N. "
            "Параллель по файлам: batch --workers N."
        )

    if args.files:
        return _run_multi_file(args, anonymizer)

    is_stdin = args.input in (None, "-")
    input_label = "stdin" if is_stdin else args.input

    # Keep file outputs closed until content is ready so atomic replace also
    # works on Windows.
    out_stream = sys.stdout if args.output in (None, "-") else (
        open(args.output, "w", encoding="utf-8") if args.stream else None)
    exit_code = EXIT_OK
    cleaned_text = None
    raw_text = None  # заполняется только когда действительно нужен целиком

    try:
        if args.stream:
            if not is_stdin and args.workers and args.workers > 1:
                # Параллельный построчный режим требует список строк для
                # деления на чанки — здесь экономия памяти недостижима,
                # но так параллелизм остаётся доступным и для больших файлов.
                raw_text = read_log_file(args.input)
                lines = raw_text.splitlines(keepends=True)
                out_lines = _run_with_profiling(
                    anonymizer.anonymize_parallel_lines, args, lines, workers=args.workers)
                out_stream.write("".join(out_lines))
            elif is_stdin:
                if args.workers and args.workers > 1:
                    lines = sys.stdin.readlines()
                    out_lines = _run_with_profiling(
                        anonymizer.anonymize_parallel_lines, args, lines, workers=args.workers)
                    out_stream.write("".join(out_lines))
                else:
                    def _process():
                        for line in anonymizer.anonymize_stream(sys.stdin):
                            out_stream.write(line)
                    _run_with_profiling(_process, args)
            else:
                # Однопоточный построчный режим — по-настоящему константный
                # объём памяти вне зависимости от размера файла: mmap
                # (--mmap), gzip-поток (файл определяется автоматически по
                # магическим байтам) либо обычное ленивое построчное чтение
                # — выбор стратегии инкапсулирован в iter_log_lines()
                # (.evtx конвертируется через wevtutil, затем читается как текст).
                def _process():
                    for line in anonymizer.anonymize_stream(
                            iter_log_lines(args.input, use_mmap=getattr(args, "use_mmap", False))):
                        out_stream.write(line)
                _run_with_profiling(_process, args)
            cleaned_text = None  # verify()/diff пропускаются в --stream для очень больших файлов
        else:
            if is_stdin:
                raw_text = sys.stdin.read()
            else:
                _check_input_size(args.input, config)
                raw_text = read_log_file(args.input)
            cleaned_text = _run_with_profiling(anonymizer.anonymize, args, raw_text)
            if args.output in (None, "-"):
                sys.stdout.write(cleaned_text)
            else:
                atomic_write_text(args.output, cleaned_text)
                # Verify the persisted bytes, not only the in-memory result.
                persisted = read_file_auto_encoding(args.output)
                if persisted != cleaned_text:
                    raise OSError("Проверка записанного результата не пройдена")
                cleaned_text = persisted
    finally:
        if out_stream is not None and out_stream is not sys.stdout:
            out_stream.close()

    if args.save_mapping:
        _save_mapping_from_args(anonymizer, args)

    if cleaned_text is not None:
        if args.diff:
            _print_diff(raw_text, cleaned_text, label=input_label)
        exit_code = _report_verify(anonymizer, cleaned_text, args.fail_on_unsafe)
    elif args.diff:
        logger.warning("--diff игнорируется в режиме --stream.")

    if args.stats:
        _log_stats(anonymizer)

    log_audit_event(config.audit_log_path, {
        "action": "anonymize",
        "source": "cli",
        "input": input_label,
        "org_name": args.org,
        "stream_mode": bool(args.stream),
        "stats_by_type": anonymizer.get_stats(),
        "unique_values_replaced": len(anonymizer.mapping_table),
        "exit_code": exit_code,
    }, max_bytes=config.audit_log_max_bytes, backup_count=config.audit_log_backup_count)

    return exit_code


def _run_multi_file(args: argparse.Namespace, anonymizer: SOCLogAnonymizer) -> int:
    """Обработка нескольких файлов/glob-шаблонов, переданных позиционными
    аргументами (альтернатива -i для разовой обработки набора файлов без
    выделенной каталожной структуры — для этого есть `batch`)."""
    expanded: List[str] = []
    for pattern in args.files:
        matches = glob.glob(pattern)
        if matches:
            expanded.extend(matches)
        elif os.path.exists(pattern):
            expanded.append(pattern)
        else:
            logger.warning("Файл/шаблон не найден: %s", pattern)

    if not expanded:
        logger.error("Ни один файл не найден по указанным шаблонам.")
        return EXIT_ERROR

    if len(expanded) > 1 and not args.output_dir:
        logger.error("Для нескольких файлов требуется --output-dir.")
        return EXIT_ERROR

    exit_code = EXIT_OK
    for file_path in expanded:
        try:
            _check_input_size(file_path, anonymizer.config)
            raw_text = read_log_file(file_path)
            cleaned_text = anonymizer.anonymize(raw_text)
        except (OSError, UnicodeError, ValueError) as exc:
            logger.error("Не удалось обработать %s: %s", file_path, exc)
            exit_code = max(exit_code, EXIT_ERROR)
            continue

        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            out_path = _output_path_for(file_path, os.path.basename(file_path), args.output_dir)
        else:
            out_path = args.output if args.output not in (None, "-") else None

        if out_path:
            atomic_write_text(out_path, cleaned_text)
            if read_file_auto_encoding(out_path) != cleaned_text:
                logger.error("Проверка записанного результата не пройдена: %s", out_path)
                exit_code = max(exit_code, EXIT_ERROR)
                continue
        else:
            sys.stdout.write(cleaned_text)

        logger.info("Обработан файл: %s", file_path)
        file_exit = _report_verify(anonymizer, cleaned_text, args.fail_on_unsafe)
        exit_code = max(exit_code, file_exit)

    if args.save_mapping:
        _save_mapping_from_args(anonymizer, args)
    if args.stats:
        _log_stats(anonymizer)

    log_audit_event(anonymizer.config.audit_log_path, {
        "action": "anonymize",
        "source": "cli",
        "files": [os.path.basename(p) for p in expanded],
        "file_count": len(expanded),
        "org_name": getattr(args, "org", None),
        "stats_by_type": anonymizer.get_stats(),
        "unique_values_replaced": len(anonymizer.mapping_table),
        "exit_code": exit_code,
    }, max_bytes=anonymizer.config.audit_log_max_bytes, backup_count=anonymizer.config.audit_log_backup_count)

    return exit_code


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files and report what would be anonymized without writing output."""
    config = _load_config_for_command(args)
    try:
        salt = _read_salt(args)
    except StrictPermsError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    anonymizer = SOCLogAnonymizer(salt=salt, org_name=args.org, config=config)
    paths = list(args.files)
    if not paths:
        paths = [args.input] if args.input not in (None, "-") else []
    expanded = []
    for pattern in paths:
        matches = glob.glob(pattern) or ([pattern] if os.path.exists(pattern) else [])
        expanded.extend(matches)
    if not expanded:
        text = sys.stdin.read()
        cleaned = anonymizer.anonymize(text)
        safe, issues = anonymizer.verify(cleaned)
        _emit_reports([{"input": "stdin", "size_bytes": len(text.encode("utf-8")),
                        "replacements": sum(anonymizer.get_stats().values()),
                        "unique_values": len(anonymizer.mapping_table),
                        "stats_by_type": anonymizer.get_stats(), "safe": safe,
                        "issues": issues}], args.format)
        return EXIT_OK
    exit_code = EXIT_OK
    reports = []
    for path in expanded:
        try:
            if args.stream:
                for line_no, line in enumerate(iter_log_lines(path), 1):
                    line_anonymizer = SOCLogAnonymizer(salt=anonymizer.salt,
                                                       org_name=args.org, config=config)
                    started = time.perf_counter()
                    cleaned_line = line_anonymizer.anonymize(line)
                    safe, issues = line_anonymizer.verify(cleaned_line)
                    item = {"input": path, "line": line_no,
                            "replacements": sum(line_anonymizer.get_stats().values()),
                            "unique_values": len(line_anonymizer.mapping_table),
                            "stats_by_type": line_anonymizer.get_stats(),
                            "safe": safe, "issues": issues,
                            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)}
                    if args.format == "jsonl":
                        _emit_reports([item], "jsonl")
                    else:
                        reports.append(item)
                    line_anonymizer.clear_sensitive_data()
                continue
            source = read_log_file(path)
            started = time.perf_counter()
            cleaned = anonymizer.anonymize(source)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            line_details = []
            for line_no, (before, after) in enumerate(zip(
                    source.splitlines(), cleaned.splitlines()), 1):
                if before == after:
                    continue
                matcher = difflib.SequenceMatcher(None, before, after)
                positions = [{"start": block.a, "end": block.a + block.size}
                             for block in matcher.get_matching_blocks()
                             if block.size == 0]
                line_details.append({"line": line_no, "positions": positions})
            safe, issues = anonymizer.verify(cleaned)
            reports.append({"input": path, "size_bytes": os.path.getsize(path),
                            "line_count": len(source.splitlines()),
                            "changed_lines": line_details,
                            "elapsed_ms": elapsed_ms,
                            "replacements": sum(anonymizer.get_stats().values()),
                            "unique_values": len(anonymizer.mapping_table),
                            "stats_by_type": anonymizer.get_stats(), "safe": safe,
                            "issues": issues, "metrics": anonymizer.get_metrics()})
        except (OSError, UnicodeError, ValueError) as exc:
            logger.error("Не удалось просканировать %s: %s", path, exc)
            exit_code = EXIT_ERROR
    _emit_reports(reports, args.format)
    return exit_code


# ----------------------------------------------------------------------
# deanonymize
# ----------------------------------------------------------------------

def cmd_deanonymize(args: argparse.Namespace) -> int:
    config = AnonymizerConfig.load(_resolve_config_path(args))
    warning = check_world_readable(args.mapping)
    if warning:
        if getattr(args, "strict_perms", False):
            logger.error("%s", warning)
            return EXIT_ERROR
        logger.warning("%s", warning)
    try:
        anonymizer = SOCLogAnonymizer.load_mapping(
            args.mapping,
            config=config,
            passphrase=_mapping_crypto_kwargs(args).get("passphrase"),
        )
    except (OSError, ValueError) as e:
        logger.error("Не удалось загрузить mapping-файл %s: %s", args.mapping, e)
        return EXIT_ERROR
    _register_atexit_cleanup(anonymizer)

    if args.input in (None, "-"):
        text = sys.stdin.read()
    else:
        text = read_file_auto_encoding(args.input)

    restored = anonymizer.deanonymize(text)

    if args.output in (None, "-"):
        sys.stdout.write(restored)
    else:
        atomic_write_text(args.output, restored)

    log_audit_event(config.audit_log_path, {
        "action": "deanonymize",
        "source": "cli",
        "mapping_file": os.path.basename(args.mapping),
        "unique_values_available": len(anonymizer.reverse_mapping),
        "exit_code": EXIT_OK,
    }, max_bytes=config.audit_log_max_bytes, backup_count=config.audit_log_backup_count)

    return EXIT_OK


# ----------------------------------------------------------------------
# batch
# ----------------------------------------------------------------------

def cmd_batch(args: argparse.Namespace) -> int:
    import fnmatch

    config = _load_config_for_command(args)

    try:
        salt = _read_salt(args)
    except StrictPermsError as e:
        logger.error("%s", e)
        return EXIT_ERROR
    # Единая соль для всех файлов каталога — обязательное условие
    # консистентности псевдонимов между файлами одного инцидента.
    anonymizer = SOCLogAnonymizer(salt=salt, org_name=args.org, config=config)
    _register_atexit_cleanup(anonymizer)
    _save_salt_if_requested(args, anonymizer)

    file_list = []
    for root, _dirs, files in os.walk(args.input_dir):
        for name in files:
            if fnmatch.fnmatch(name, args.pattern):
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, args.input_dir)
                file_list.append((full_path, rel_path))

    if not file_list:
        logger.error("Файлы по шаблону %r в %s не найдены.", args.pattern, args.input_dir)
        return EXIT_ERROR

    logger.info("Найдено файлов: %d", len(file_list))

    if args.dry_run:
        reports = []
        for full_path, rel_path in file_list:
            try:
                text = read_log_file(full_path)
                analyzer = SOCLogAnonymizer(salt=anonymizer.salt, org_name=args.org,
                                           config=config)
                cleaned = analyzer.anonymize(text)
                safe, issues = analyzer.verify(cleaned)
                reports.append({"input": rel_path, "size_bytes": os.path.getsize(full_path),
                                "replacements": sum(analyzer.get_stats().values()),
                                "unique_values": len(analyzer.mapping_table),
                                "stats_by_type": analyzer.get_stats(), "safe": safe,
                                "issues": issues})
            except (OSError, UnicodeError, ValueError) as exc:
                reports.append({"input": rel_path, "size_bytes": 0,
                                "replacements": 0, "unique_values": 0,
                                "stats_by_type": {}, "safe": False,
                                "issues": [str(exc)]})
        _emit_reports(reports, getattr(args, "format", "jsonl"))
        return EXIT_ERROR if any(not item["safe"] for item in reports) else EXIT_OK

    progress = _Progress(len(file_list), args) if (
        getattr(args, "progress", False) or getattr(args, "progress_events", False)
    ) else None
    if args.workers and args.workers > 1:
        _run_with_profiling(_batch_parallel, args, anonymizer, file_list, args, progress)
    else:
        def _process_all():
            for index, (full_path, rel_path) in enumerate(file_list, 1):
                _process_one_batch_file(anonymizer, full_path, rel_path, args.output_dir)
                logger.info("  OK %s", rel_path)
                if progress:
                    progress.update(rel_path)
        _run_with_profiling(_process_all, args)
    if progress:
        progress.finish()

    if args.save_mapping:
        _save_mapping_from_args(anonymizer, args)
    if args.stats:
        _log_stats(anonymizer)

    exit_code = EXIT_OK
    if args.fail_on_unsafe:
        exit_code = _batch_verify_all(anonymizer, file_list, args.output_dir)

    is_parallel = bool(args.workers and args.workers > 1)
    log_audit_event(anonymizer.config.audit_log_path, {
        "action": "batch",
        "source": "cli",
        "input_dir_basename": os.path.basename(os.path.normpath(args.input_dir)),
        "pattern": args.pattern,
        "file_count": len(file_list),
        "org_name": getattr(args, "org", None),
        "parallel_workers": args.workers if is_parallel else None,
        # В параллельном режиме каждый воркер — отдельный процесс со своим
        # SOCLogAnonymizer (см. _batch_worker), поэтому статистика этого,
        # главного, экземпляра неполна — не выдаём её как достоверную.
        "stats_by_type": None if is_parallel else anonymizer.get_stats(),
        "unique_values_replaced": None if is_parallel else len(anonymizer.mapping_table),
        "exit_code": exit_code,
    }, max_bytes=anonymizer.config.audit_log_max_bytes, backup_count=anonymizer.config.audit_log_backup_count)

    return exit_code


def _batch_verify_all(anonymizer: SOCLogAnonymizer, file_list, output_dir: str) -> int:
    """Отдельный проход verify() по уже записанным результатам —
    используется только если запрошен --fail-on-unsafe (по умолчанию
    batch не тратит на это лишний проход по каждому файлу)."""
    exit_code = EXIT_OK
    for full_path, rel_path in file_list:
        out_path = _output_path_for(full_path, rel_path, output_dir)
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                cleaned_text = f.read()
        except OSError:
            continue
        is_safe, file_issues = anonymizer.verify(cleaned_text)
        if not is_safe:
            for issue in file_issues:
                logger.warning("Gatekeeper [%s]: %s", rel_path, issue)
            exit_code = EXIT_UNSAFE
    return exit_code


def _process_one_batch_file(anonymizer: SOCLogAnonymizer, full_path: str, rel_path: str, output_dir: str) -> None:
    _check_input_size(full_path, anonymizer.config)
    raw_text = read_log_file(full_path)
    cleaned_text = anonymizer.anonymize(raw_text)
    out_path = _output_path_for(full_path, rel_path, output_dir)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    atomic_write_text(out_path, cleaned_text)


def _batch_parallel(anonymizer: SOCLogAnonymizer, file_list, args: argparse.Namespace,
                    progress: Optional[_Progress] = None) -> None:
    """Параллельная обработка на уровне файлов: каждый воркер обрабатывает
    один файл целиком той же солью/конфигурацией, после чего таблицы
    соответствия объединяются в главном процессе детерминированно."""
    from concurrent.futures import ProcessPoolExecutor

    tasks = [(full_path, rel_path, anonymizer.salt, anonymizer._hmac_key,
              anonymizer.config.as_dict(), args.output_dir)
             for full_path, rel_path in file_list]

    worker_mappings = []
    outputs = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for rel_path, mapping, stats, out_path in executor.map(_batch_worker, tasks):
            worker_mappings.append(mapping)
            outputs.append((rel_path, out_path))
            anonymizer.stats.update(stats)
            logger.info("  OK %s", rel_path)
            if progress:
                progress.update(rel_path)

    if anonymizer.mapping_table:
        worker_mappings = [dict(anonymizer.mapping_table)] + worker_mappings
    canonical, reverse = merge_mappings_deterministic(worker_mappings)
    rewrite = build_pseudo_rewrite(worker_mappings, canonical)
    install_merged_mapping(
        anonymizer.mapping_table, anonymizer.reverse_mapping, canonical, reverse,
    )
    if rewrite:
        for _rel_path, out_path in outputs:
            try:
                with open(out_path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                atomic_write_text(out_path, apply_pseudo_rewrite(text, rewrite))
            except OSError as exc:
                logger.warning("Не удалось переписать %s после merge mapping: %s", out_path, exc)


def _batch_worker(task):
    """Функция верхнего уровня модуля (picklable) для ProcessPoolExecutor.
    Ключ передан уже выведенным из родительского процесса (см.
    _batch_parallel) — PBKDF2 здесь НЕ повторяется на каждый файл."""
    full_path, rel_path, salt, hmac_key, config_dict, output_dir = task
    config = AnonymizerConfig(**config_dict)
    local = SOCLogAnonymizer(salt=salt, config=config, _prederived_key=hmac_key)
    raw_text = read_log_file(full_path)
    cleaned_text = local.anonymize(raw_text)
    out_path = _output_path_for(full_path, rel_path, output_dir)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    atomic_write_text(out_path, cleaned_text)
    return rel_path, local.mapping_table, dict(local.stats), out_path


# ----------------------------------------------------------------------
# verify-result
# ----------------------------------------------------------------------

def cmd_verify_result(args: argparse.Namespace) -> int:
    """Verify already produced result files; never anonymizes or rewrites them."""
    config = _load_config_for_command(args)
    try:
        salt = _read_salt(args)
    except StrictPermsError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    verifier = SOCLogAnonymizer(salt=salt, org_name=args.org, config=config)
    paths = list(args.files)
    if args.input_dir:
        for root, _dirs, names in os.walk(args.input_dir):
            for name in names:
                if fnmatch.fnmatch(name, args.pattern):
                    paths.append(os.path.join(root, name))
    expanded = []
    for path in paths:
        expanded.extend(glob.glob(path) or ([path] if os.path.isfile(path) else []))
    if not expanded:
        logger.error("Файлы результатов не найдены.")
        return EXIT_ERROR
    reports = []
    exit_code = EXIT_OK
    for path in expanded:
        try:
            text = read_file_auto_encoding(path)
            safe, issues = verifier.verify(text)
            report = {"input": path, "size_bytes": os.path.getsize(path),
                      "line_count": len(text.splitlines()), "safe": safe,
                      "issues": issues}
            reports.append(report)
            if not safe and args.fail_on_unsafe:
                exit_code = EXIT_UNSAFE
        except (OSError, UnicodeError, ValueError) as exc:
            reports.append({"input": path, "size_bytes": 0, "line_count": 0,
                            "safe": False, "issues": [str(exc)]})
            exit_code = EXIT_ERROR
    _emit_reports(reports, args.format)
    return exit_code


# ----------------------------------------------------------------------
# validate-config
# ----------------------------------------------------------------------

def cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        config = AnonymizerConfig.load(args.config_path)
    except (OSError, ValueError) as e:
        logger.error("Не удалось загрузить конфигурацию %s: %s", args.config_path, e)
        return EXIT_ERROR

    issues = config.validate()
    if getattr(args, "fix", False):
        config.save(args.config_path)
        logger.info("Конфигурация нормализована и сохранена: %s", args.config_path)
    if not issues:
        logger.info("Конфигурация %s корректна.", args.config_path)
        print(f"OK: {args.config_path} — проблем не найдено.")
        return EXIT_OK

    print(f"Найдено проблем: {len(issues)}")
    for issue in issues:
        print(f"  - {issue}")
    return EXIT_ERROR


def cmd_diff_config(args: argparse.Namespace) -> int:
    left = AnonymizerConfig.load(args.left)
    right = AnonymizerConfig.load(args.right)
    a, b = left.as_dict(), right.as_dict()
    differences = {key: {"left": a.get(key), "right": b.get(key)}
                   for key in sorted(set(a) | set(b)) if a.get(key) != b.get(key)}
    print(json.dumps(differences, ensure_ascii=False, indent=2))
    return EXIT_OK if not differences else EXIT_ERROR


# ----------------------------------------------------------------------
# Парсер аргументов
# ----------------------------------------------------------------------

def _add_common_logging_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-v", "--verbose", action="count", default=0,
                         help="Увеличить детализацию лога (-v: INFO, -vv: DEBUG)")
    parser.add_argument("--log-file", help="Файл журнала работы инструмента (ротация 5МБ x5, только метаданные)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_log_anonymizer",
        description="Анонимизация логов SOC перед отправкой во внешнюю LLM.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- anonymize ---
    p_anon = subparsers.add_parser("anonymize", help="Анонимизировать файл(ы) или stdin")
    p_anon.add_argument("files", nargs="*",
                         help="Один или несколько файлов/glob-шаблонов (альтернатива -i для набора файлов)")
    p_anon.add_argument("-i", "--input", help="Входной файл (по умолчанию: stdin)")
    p_anon.add_argument("-o", "--output", help="Выходной файл (по умолчанию: stdout)")
    p_anon.add_argument("--output-dir", help="Каталог для результатов при указании нескольких files")
    p_anon.add_argument("--org", default=os.environ.get(ENV_ORG), help="Название организации для маскирования")
    p_anon.add_argument("--config", help=f"Путь к JSON/INI-файлу конфигурации (или переменная {ENV_CONFIG})")
    salt_group = p_anon.add_mutually_exclusive_group()
    salt_group.add_argument("--salt", help="Соль (не рекомендуется — используйте --salt-file)")
    salt_group.add_argument("--salt-file", help=f"Файл с солью (или переменная {ENV_SALT_FILE})")
    p_anon.add_argument("--save-salt", help="Сохранить сгенерированную соль в файл (права 0600)")
    p_anon.add_argument("--save-mapping", help="Сохранить таблицу соответствия в JSON (права 0600)")
    _add_mapping_crypto_args(p_anon)
    p_anon.add_argument("--stats", action="store_true", help="Вывести статистику замен")
    p_anon.add_argument("--diff", action="store_true", help="Вывести unified diff в stderr")
    p_anon.add_argument("--stream", action="store_true",
                         help="Построчная обработка (низкое потребление памяти на больших файлах)")
    p_anon.add_argument("--workers", type=int, default=1,
                         help="Параллель только с --stream (по строкам). Для каталога — batch --workers")
    p_anon.add_argument("--mmap", dest="use_mmap", action="store_true",
                         help="Построчное чтение через mmap вместо обычного открытия файла "
                              "(--stream, однопоточный режим); эффективнее на очень больших файлах. "
                              "Игнорируется для .gz-файлов (используется gzip-поток вместо mmap)")
    p_anon.add_argument("--profile", action="store_true",
                         help="Профилировать CPU через cProfile, top-20 в лог (уровень INFO)")
    p_anon.add_argument("--profile-memory", action="store_true",
                         help="Отслеживать пиковое потребление памяти через tracemalloc")
    p_anon.add_argument("--fail-on-unsafe", action="store_true",
                         help=f"Возвращать код {EXIT_UNSAFE}, если gatekeeper (verify()) нашёл проблемы")
    p_anon.add_argument("--strict-perms", action="store_true",
                         help=f"Возвращать код {EXIT_ERROR}, если --salt-file доступен на чтение другим "
                              f"пользователям системы, вместо предупреждения в лог")
    p_anon.add_argument("--strict-config", action="store_true",
                         help="Завершить с ошибкой при любой проблеме конфигурации")
    _add_common_logging_args(p_anon)
    p_anon.set_defaults(func=cmd_anonymize)

    # --- deanonymize ---
    p_dean = subparsers.add_parser("deanonymize", help="Восстановить исходные значения по mapping-файлу")
    p_dean.add_argument("-i", "--input", help="Входной файл (по умолчанию: stdin)")
    p_dean.add_argument("-o", "--output", help="Выходной файл (по умолчанию: stdout)")
    p_dean.add_argument("--mapping", required=True, help="JSON-файл, сохранённый флагом --save-mapping")
    _add_mapping_crypto_args(p_dean, for_load=True)
    p_dean.add_argument("--config", help=f"Путь к JSON/INI-файлу конфигурации (или переменная {ENV_CONFIG})")
    p_dean.add_argument("--strict-perms", action="store_true",
                         help=f"Возвращать код {EXIT_ERROR}, если --mapping доступен на чтение другим "
                              f"пользователям системы, вместо предупреждения в лог")
    _add_common_logging_args(p_dean)
    p_dean.set_defaults(func=cmd_deanonymize)

    # --- batch ---
    p_batch = subparsers.add_parser("batch", help="Пакетная анонимизация каталога логов")
    p_batch.add_argument("--input-dir", required=True, help="Каталог с исходными логами")
    p_batch.add_argument("--output-dir", required=True, help="Каталог для анонимизированных логов")
    p_batch.add_argument("--pattern", default="*", help="Glob-шаблон имён файлов (по умолчанию: все файлы)")
    p_batch.add_argument("--org", default=os.environ.get(ENV_ORG), help="Название организации для маскирования")
    p_batch.add_argument("--config", help=f"Путь к JSON/INI-файлу конфигурации (или переменная {ENV_CONFIG})")
    salt_group_b = p_batch.add_mutually_exclusive_group()
    salt_group_b.add_argument("--salt", help="Соль (не рекомендуется — используйте --salt-file)")
    salt_group_b.add_argument("--salt-file", help=f"Файл с солью (или переменная {ENV_SALT_FILE})")
    p_batch.add_argument("--save-salt", help="Сохранить сгенерированную соль в файл (права 0600)")
    p_batch.add_argument("--save-mapping", help="Сохранить объединённую таблицу соответствия в JSON (права 0600)")
    _add_mapping_crypto_args(p_batch)
    p_batch.add_argument("--stats", action="store_true", help="Вывести статистику замен")
    p_batch.add_argument("--workers", type=int, default=1, help="Число параллельных процессов (по файлам)")
    p_batch.add_argument("--profile", action="store_true",
                          help="Профилировать CPU через cProfile, top-20 в лог (уровень INFO)")
    p_batch.add_argument("--profile-memory", action="store_true",
                          help="Отслеживать пиковое потребление памяти через tracemalloc")
    p_batch.add_argument("--fail-on-unsafe", action="store_true",
                          help=f"Возвращать код {EXIT_UNSAFE}, если gatekeeper нашёл проблемы хотя бы в одном файле")
    p_batch.add_argument("--strict-perms", action="store_true",
                          help=f"Возвращать код {EXIT_ERROR}, если --salt-file доступен на чтение другим "
                               f"пользователям системы, вместо предупреждения в лог")
    p_batch.add_argument("--strict-config", action="store_true",
                         help="Завершить с ошибкой при любой проблеме конфигурации")
    p_batch.add_argument("--dry-run", action="store_true",
                         help="Только проверить и отчитаться, не создавая выходные файлы")
    p_batch.add_argument("--format", choices=("jsonl", "json", "csv"),
                         default=os.environ.get(ENV_REPORT_FORMAT, "jsonl"))
    p_batch.add_argument("--progress-events", action="store_true",
                         help="Печатать JSON-события прогресса (с ETA и скоростью) в stderr")
    p_batch.add_argument("--progress", action="store_true",
                         help="Печатать человекочитаемый прогресс, скорость и ETA в stderr")
    _add_common_logging_args(p_batch)
    p_batch.set_defaults(func=cmd_batch)

    # --- scan ---
    p_scan = subparsers.add_parser("scan", help="Просканировать лог без записи результата")
    p_scan.add_argument("files", nargs="*", help="Файлы или glob-шаблоны")
    p_scan.add_argument("-i", "--input", help="Один входной файл (или stdin)")
    p_scan.add_argument("--org", default=os.environ.get(ENV_ORG))
    p_scan.add_argument("--config", help=f"Путь к JSON/INI-файлу (или {ENV_CONFIG})")
    scan_salt = p_scan.add_mutually_exclusive_group()
    scan_salt.add_argument("--salt")
    scan_salt.add_argument("--salt-file", help=f"Файл соли (или {ENV_SALT_FILE})")
    p_scan.add_argument("--strict-perms", action="store_true")
    p_scan.add_argument("--strict-config", action="store_true")
    p_scan.add_argument("--format", choices=("jsonl", "json", "csv"),
                        default=os.environ.get(ENV_REPORT_FORMAT, "jsonl"),
                        help="Формат отчета: jsonl, json или csv")
    p_scan.add_argument("--stream", action="store_true",
                        help="Сканировать построчно, не загружая файл целиком")
    _add_common_logging_args(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    # --- verify-result ---
    p_verify = subparsers.add_parser(
        "verify-result",
        help="Проверить уже созданные результаты без повторной обработки",
    )
    p_verify.add_argument("files", nargs="*", help="Файлы или glob-шаблоны результатов")
    p_verify.add_argument("-i", "--input-dir", help="Каталог результатов для проверки")
    p_verify.add_argument("--pattern", default="*", help="Шаблон имён при --input-dir")
    p_verify.add_argument("--org", default=os.environ.get(ENV_ORG))
    p_verify.add_argument("--config", help=f"Путь к JSON/INI-файлу (или {ENV_CONFIG})")
    verify_salt = p_verify.add_mutually_exclusive_group()
    verify_salt.add_argument("--salt")
    verify_salt.add_argument("--salt-file", help=f"Файл соли (или {ENV_SALT_FILE})")
    p_verify.add_argument("--strict-perms", action="store_true")
    p_verify.add_argument("--strict-config", action="store_true")
    p_verify.add_argument("--fail-on-unsafe", action="store_true",
                          help=f"Возвращать код {EXIT_UNSAFE} для небезопасного результата")
    p_verify.add_argument("--format", choices=("jsonl", "json", "csv"),
                          default=os.environ.get(ENV_REPORT_FORMAT, "jsonl"),
                          help="Формат отчёта: jsonl, json или csv")
    _add_common_logging_args(p_verify)
    p_verify.set_defaults(func=cmd_verify_result)

    # --- validate-config ---
    p_validate = subparsers.add_parser("validate-config", help="Проверить JSON/INI-конфигурацию")
    p_validate.add_argument("config_path", help="Путь к файлу конфигурации")
    p_validate.add_argument("--fix", action="store_true",
                            help="Нормализовать и сохранить конфигурацию после проверки")
    _add_common_logging_args(p_validate)
    p_validate.set_defaults(func=cmd_validate_config)

    p_diff = subparsers.add_parser("diff-config", help="Сравнить две конфигурации")
    p_diff.add_argument("left")
    p_diff.add_argument("right")
    _add_common_logging_args(p_diff)
    p_diff.set_defaults(func=cmd_diff_config)

    return parser


def main(argv=None) -> int:
    _configure_stdio()
    _install_signal_handlers()
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", 0), getattr(args, "log_file", None))
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        logger.error("Ошибка выполнения: %s", e)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
