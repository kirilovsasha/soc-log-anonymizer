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
import difflib
import glob
import io as _io
import json
import logging
import os
import pstats
import signal
import sys
import tracemalloc
from logging.handlers import RotatingFileHandler
from typing import List, Optional, Tuple

from . import __version__
from .anonymizer import SOCLogAnonymizer
from .audit import log_audit_event
from .config import AnonymizerConfig
from .io_utils import (
    check_world_readable,
    format_size_mb,
    is_gzip_file,
    iter_lines_stream,
    read_file_auto_encoding,
)

logger = logging.getLogger("soc_log_anonymizer")

ENV_SALT_FILE = "SOC_ANON_SALT_FILE"
ENV_CONFIG = "SOC_ANON_CONFIG"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNSAFE = 2


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
    return getattr(args, "config", None) or os.environ.get(ENV_CONFIG)


def _save_salt_if_requested(args: argparse.Namespace, anonymizer: SOCLogAnonymizer) -> None:
    if getattr(args, "save_salt", None):
        fd = os.open(args.save_salt, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(anonymizer.salt)
        logger.info("Соль сохранена в %s (права доступа 0600)", args.save_salt)


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


# ----------------------------------------------------------------------
# anonymize
# ----------------------------------------------------------------------

def cmd_anonymize(args: argparse.Namespace) -> int:
    config = AnonymizerConfig.load(_resolve_config_path(args))
    for issue in config.validate():
        logger.warning("Проблема конфигурации: %s", issue)

    try:
        salt = _read_salt(args)
    except StrictPermsError as e:
        logger.error("%s", e)
        return EXIT_ERROR
    anonymizer = SOCLogAnonymizer(salt=salt, org_name=args.org, config=config)
    _register_atexit_cleanup(anonymizer)
    _save_salt_if_requested(args, anonymizer)

    if args.files:
        return _run_multi_file(args, anonymizer)

    is_stdin = args.input in (None, "-")
    input_label = "stdin" if is_stdin else args.input

    out_stream = sys.stdout if args.output in (None, "-") else open(args.output, "w", encoding="utf-8")
    exit_code = EXIT_OK
    cleaned_text = None
    raw_text = None  # заполняется только когда действительно нужен целиком

    try:
        if args.stream:
            if not is_stdin and args.workers and args.workers > 1:
                # Параллельный построчный режим требует список строк для
                # деления на чанки — здесь экономия памяти недостижима,
                # но так параллелизм остаётся доступным и для больших файлов.
                raw_text = read_file_auto_encoding(args.input)
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
                # — выбор стратегии инкапсулирован в iter_lines_stream().
                def _process():
                    for line in anonymizer.anonymize_stream(
                            iter_lines_stream(args.input, use_mmap=getattr(args, "use_mmap", False))):
                        out_stream.write(line)
                _run_with_profiling(_process, args)
            cleaned_text = None  # verify()/diff пропускаются в --stream для очень больших файлов
        else:
            if is_stdin:
                raw_text = sys.stdin.read()
            else:
                _check_input_size(args.input, config)
                raw_text = read_file_auto_encoding(args.input)
            cleaned_text = _run_with_profiling(anonymizer.anonymize, args, raw_text)
            out_stream.write(cleaned_text)
    finally:
        if out_stream is not sys.stdout:
            out_stream.close()

    if args.save_mapping:
        anonymizer.save_mapping(args.save_mapping)

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
        _check_input_size(file_path, anonymizer.config)
        raw_text = read_file_auto_encoding(file_path)
        cleaned_text = anonymizer.anonymize(raw_text)

        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            out_path = _output_path_for(file_path, os.path.basename(file_path), args.output_dir)
        else:
            out_path = args.output if args.output not in (None, "-") else None

        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(cleaned_text)
        else:
            sys.stdout.write(cleaned_text)

        logger.info("Обработан файл: %s", file_path)
        file_exit = _report_verify(anonymizer, cleaned_text, args.fail_on_unsafe)
        exit_code = max(exit_code, file_exit)

    if args.save_mapping:
        anonymizer.save_mapping(args.save_mapping)
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
        anonymizer = SOCLogAnonymizer.load_mapping(args.mapping, config=config)
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
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(restored)

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

    config = AnonymizerConfig.load(_resolve_config_path(args))
    issues = config.validate()
    for issue in issues:
        logger.warning("Проблема конфигурации: %s", issue)

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

    if args.workers and args.workers > 1:
        _run_with_profiling(_batch_parallel, args, anonymizer, file_list, args)
    else:
        def _process_all():
            for full_path, rel_path in file_list:
                _process_one_batch_file(anonymizer, full_path, rel_path, args.output_dir)
                logger.info("  OK %s", rel_path)
        _run_with_profiling(_process_all, args)

    if args.save_mapping:
        anonymizer.save_mapping(args.save_mapping)
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
    raw_text = read_file_auto_encoding(full_path)
    cleaned_text = anonymizer.anonymize(raw_text)
    out_path = _output_path_for(full_path, rel_path, output_dir)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(cleaned_text)


def _batch_parallel(anonymizer: SOCLogAnonymizer, file_list, args: argparse.Namespace) -> None:
    """Параллельная обработка на уровне файлов: каждый воркер обрабатывает
    один файл целиком той же солью/конфигурацией, после чего таблицы
    соответствия объединяются в главном процессе. Хэш — чистая функция от
    (HMAC-ключ, значение), поэтому консистентность псевдонимов между
    файлами, обработанными в разных процессах, сохраняется."""
    from concurrent.futures import ProcessPoolExecutor

    # anonymizer._hmac_key передаётся уже выведенным (PBKDF2 прогнан один
    # раз здесь) — без этого каждый из args.workers процессов (а при
    # батче из сотен файлов это сотни ЗАДАЧ, распределяемых по пулу из
    # нескольких воркеров, но каждая задача — новый SOCLogAnonymizer)
    # заново прогонял бы 600 000 итераций ради того же самого ключа.
    tasks = [(full_path, rel_path, anonymizer.salt, anonymizer._hmac_key,
              anonymizer.config.as_dict(), args.output_dir)
             for full_path, rel_path in file_list]

    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for rel_path, mapping, stats in executor.map(_batch_worker, tasks):
            anonymizer.mapping_table.update(mapping)
            for orig, pseudo in mapping.items():
                anonymizer.reverse_mapping[pseudo] = orig
            anonymizer.stats.update(stats)
            logger.info("  OK %s", rel_path)


def _batch_worker(task):
    """Функция верхнего уровня модуля (picklable) для ProcessPoolExecutor.
    Ключ передан уже выведенным из родительского процесса (см.
    _batch_parallel) — PBKDF2 здесь НЕ повторяется на каждый файл."""
    full_path, rel_path, salt, hmac_key, config_dict, output_dir = task
    config = AnonymizerConfig(**config_dict)
    local = SOCLogAnonymizer(salt=salt, config=config, _prederived_key=hmac_key)
    raw_text = read_file_auto_encoding(full_path)
    cleaned_text = local.anonymize(raw_text)
    out_path = _output_path_for(full_path, rel_path, output_dir)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(cleaned_text)
    return rel_path, local.mapping_table, dict(local.stats)


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
    if not issues:
        logger.info("Конфигурация %s корректна.", args.config_path)
        print(f"OK: {args.config_path} — проблем не найдено.")
        return EXIT_OK

    print(f"Найдено проблем: {len(issues)}")
    for issue in issues:
        print(f"  - {issue}")
    return EXIT_ERROR


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
    p_anon.add_argument("--org", default=None, help="Название организации для маскирования")
    p_anon.add_argument("--config", help=f"Путь к JSON/INI-файлу конфигурации (или переменная {ENV_CONFIG})")
    salt_group = p_anon.add_mutually_exclusive_group()
    salt_group.add_argument("--salt", help="Соль (не рекомендуется — используйте --salt-file)")
    salt_group.add_argument("--salt-file", help=f"Файл с солью (или переменная {ENV_SALT_FILE})")
    p_anon.add_argument("--save-salt", help="Сохранить сгенерированную соль в файл (права 0600)")
    p_anon.add_argument("--save-mapping", help="Сохранить таблицу соответствия в JSON (права 0600)")
    p_anon.add_argument("--stats", action="store_true", help="Вывести статистику замен")
    p_anon.add_argument("--diff", action="store_true", help="Вывести unified diff в stderr")
    p_anon.add_argument("--stream", action="store_true",
                         help="Построчная обработка (низкое потребление памяти на больших файлах)")
    p_anon.add_argument("--workers", type=int, default=1,
                         help="Число процессов для параллельной обработки")
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
    _add_common_logging_args(p_anon)
    p_anon.set_defaults(func=cmd_anonymize)

    # --- deanonymize ---
    p_dean = subparsers.add_parser("deanonymize", help="Восстановить исходные значения по mapping-файлу")
    p_dean.add_argument("-i", "--input", help="Входной файл (по умолчанию: stdin)")
    p_dean.add_argument("-o", "--output", help="Выходной файл (по умолчанию: stdout)")
    p_dean.add_argument("--mapping", required=True, help="JSON-файл, сохранённый флагом --save-mapping")
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
    p_batch.add_argument("--org", default=None, help="Название организации для маскирования")
    p_batch.add_argument("--config", help=f"Путь к JSON/INI-файлу конфигурации (или переменная {ENV_CONFIG})")
    salt_group_b = p_batch.add_mutually_exclusive_group()
    salt_group_b.add_argument("--salt", help="Соль (не рекомендуется — используйте --salt-file)")
    salt_group_b.add_argument("--salt-file", help=f"Файл с солью (или переменная {ENV_SALT_FILE})")
    p_batch.add_argument("--save-salt", help="Сохранить сгенерированную соль в файл (права 0600)")
    p_batch.add_argument("--save-mapping", help="Сохранить объединённую таблицу соответствия в JSON (права 0600)")
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
    _add_common_logging_args(p_batch)
    p_batch.set_defaults(func=cmd_batch)

    # --- validate-config ---
    p_validate = subparsers.add_parser("validate-config", help="Проверить JSON/INI-конфигурацию")
    p_validate.add_argument("config_path", help="Путь к файлу конфигурации")
    _add_common_logging_args(p_validate)
    p_validate.set_defaults(func=cmd_validate_config)

    return parser


def main(argv=None) -> int:
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
