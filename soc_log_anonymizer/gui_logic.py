"""
GUI logic kept free from tkinter imports so it can be unit-tested in headless CI.
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

MIN_SALT_LEN = 16


def salt_entropy_warning(salt: str) -> Optional[str]:
    """Warn when the salt is too short or too low-entropy."""
    if len(salt) < MIN_SALT_LEN:
        return (f"Salt is shorter than {MIN_SALT_LEN} characters ({len(salt)}). "
                f"A minimum of 32 hex chars (16 bytes) is recommended to make mapping tables harder to brute-force.")
    if len(set(salt)) < 6:
        return "Salt has low diversity; it looks like a predictable or non-random string."
    return None


def format_result_status(is_safe: bool, issues: List[str]) -> Tuple[str, str]:
    """Return a friendly status string and ttk style name for the result label."""
    if is_safe:
        return "Безопасно для LLM", "Success"
    first_issue = issues[0] if issues else "Неизвестный риск"
    extra = f" (+{len(issues) - 1})" if len(issues) > 1 else ""
    return f"Ошибка: {first_issue}{extra}", "Danger"


def compute_progress_pct(done: int, total: int) -> int:
    """Progress percentage for the UI, clamped for total<=0."""
    if total <= 0:
        return 100
    pct = int(done / total * 100)
    return max(0, min(100, pct))


def status_style_name(kind: str) -> str:
    """Return a ttk style name for a status kind."""
    return f"Status{kind.capitalize()}.TLabel"


def format_size_warning(size_mb: float, limit_mb: int) -> str:
    """Text used for warning the user when a file is too big for full in-memory processing."""
    return (f"Selected file size is {size_mb:.1f} MB, exceeding the recommended limit of {limit_mb} MB for full in-memory processing. "
            f"This can noticeably slow the interface or exhaust memory for very large logs.")


def find_context_snippet(text: str, value: str, radius: int = 40) -> str:
    """Return the text surrounding the first occurrence of value."""
    if not value:
        return "(пустое значение)"
    idx = text.find(value)
    if idx == -1:
        return "(контекст не найден в текущем вводе)"
    start = max(0, idx - radius)
    end = min(len(text), idx + len(value) + radius)
    snippet = text[start:end].replace("\n", " ").replace("\t", " ")
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def validate_regex_pattern(pattern: str, sample: str = "", strategy: str = "full") -> Tuple[bool, str]:
    """Validate a regex and, when sample is supplied, ensure it matches according to the configured strategy."""
    if not pattern or not str(pattern).strip():
        return False, "Empty regex pattern."
    try:
        regex = re.compile(str(pattern))
    except re.error as exc:
        return False, f"Invalid regex: {exc}"
    if not sample:
        return True, "Regex is valid."
    sample_text = str(sample)
    strategy_name = str(strategy or "full").lower()
    matched = bool(regex.fullmatch(sample_text)) if strategy_name == "full" else bool(regex.search(sample_text))
    if matched:
        return True, "Regex is valid and matches the sample."
    return False, f"Regex does not match the sample for strategy {strategy_name!r}."


def summarize_active_rules(custom_patterns: Optional[Iterable[Dict[str, Any]]] = None,
                          context_rules: Optional[Iterable[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Summarize active custom/context rules for a GUI rule table and validation panel."""
    rows: List[Dict[str, Any]] = []
    for item in custom_patterns or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("tag") or item.get("type") or "CUSTOM").strip()
        if not name:
            name = "CUSTOM"
        pattern = item.get("pattern") or item.get("regex") or ""
        strategy = str(item.get("strategy") or "full").lower()
        enabled = bool(item.get("enabled", True))
        priority = int(item.get("priority", 0) or 0)
        valid, _ = validate_regex_pattern(pattern, item.get("test_string", ""), strategy)
        rows.append({
            "name": name,
            "type": "custom_pattern",
            "enabled": enabled,
            "priority": priority,
            "strategy": strategy,
            "pattern": str(pattern),
            "valid": valid,
        })
    for idx, item in enumerate(context_rules or []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("id") or f"context_rule_{idx}").strip()
        if not name:
            name = f"context_rule_{idx}"
        pattern = item.get("pattern") or item.get("regex") or ""
        strategy = str(item.get("strategy") or "search").lower()
        enabled = bool(item.get("enabled", True))
        priority = int(item.get("priority", 0) or 0)
        valid, _ = validate_regex_pattern(pattern, item.get("test_string", ""), strategy)
        rows.append({
            "name": name,
            "type": "context_rule",
            "enabled": enabled,
            "priority": priority,
            "strategy": strategy,
            "pattern": str(pattern),
            "valid": valid,
        })
    return rows


def detect_rule_conflicts(custom_patterns: Optional[Iterable[Dict[str, Any]]] = None,
                         context_rules: Optional[Iterable[Dict[str, Any]]] = None) -> List[str]:
    """Find simple name/pattern conflicts in the active rule set."""
    conflicts: List[str] = []
    rows = summarize_active_rules(custom_patterns, context_rules)
    names = {}
    patterns = {}
    kind_counts = {}
    for row in rows:
        name_key = row["name"].lower()
        names[name_key] = names.get(name_key, 0) + 1
        if names[name_key] > 1:
            conflicts.append(f"Duplicate name: {row['name']} appears {names[name_key]} times.")
        pat = row["pattern"]
        if pat:
            bucket = patterns.setdefault(pat, [])
            bucket.append(row["name"])
            if len(bucket) > 1:
                conflicts.append(f"Repeated pattern: {pat!r} is used by {', '.join(sorted(set(bucket)))}.")
        kind = row["type"]
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        if kind_counts[kind] > 1:
            conflicts.append(f"Multiple {kind} rules: {kind_counts[kind]} entries.")
    unique = []
    seen = set()
    for item in conflicts:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def changed_line_numbers(original: str, cleaned: str) -> Tuple[List[int], List[int]]:
    """Return 1-based changed line numbers for the input and output panes.

    Оставлено для обратной совместимости (тесты, HTML-отчёт). Для
    подсветки в Input/Output используется `changed_value_spans` /
    `inline_diff_spans`: построчная гранулярность подсвечивает строку
    целиком, хотя реально изменилось одно значение в ней.
    """
    import difflib

    left = original.splitlines()
    right = cleaned.splitlines()
    left_numbers: List[int] = []
    right_numbers: List[int] = []
    matcher = difflib.SequenceMatcher(a=left, b=right)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        left_numbers.extend(range(i1 + 1, i2 + 1))
        right_numbers.extend(range(j1 + 1, j2 + 1))
    return left_numbers, right_numbers


# ----------------------------------------------------------------------
# Diff на уровне ЗНАЧЕНИЙ, а не строк
# ----------------------------------------------------------------------
#
# Основной путь — `changed_value_spans`: таблица соответствия уже точно
# знает, ЧТО на что заменено, поэтому искать различия эвристикой
# (difflib по символам/строкам) не нужно вообще — достаточно найти
# фактические значения в тексте. Это и точнее (подсвечивается ровно
# значение, а не строка вокруг него), и быстрее: один прохода
# скомпилированным alternation-регэкспом вместо N независимых поисков.
#
# `inline_diff_spans` — фолбэк для случая, когда таблицы нет или она
# пуста (например, пользователь вручную правил Output, или diff строится
# между двумя произвольными текстами): пословный difflib с отбрасыванием
# неизменившихся токенов.

MAX_DIFF_TOKENS = 200_000

_TOKEN_RE = re.compile(r"\w+|[^\w\s]|\s+")


def merge_spans(spans: List[Tuple[int, int]], gap: int = 0) -> List[Tuple[int, int]]:
    """Схлопывает пересекающиеся и вплотную идущие диапазоны."""
    if not spans:
        return []
    ordered = sorted(spans)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + gap:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def typed_value_spans(text: str, types: Dict[str, str],
                     default_type: str = "VALUE") -> List[Tuple[int, int, str]]:
    """Как changed_value_spans, но с типом данных для каждого диапазона.

    types: {значение: тип} — для Input это {исходное значение: тип},
    для Output {псевдоним: тип}. Тип нужен, чтобы подсветка diff'а
    красила IP, логины и секреты РАЗНЫМИ цветами, а не одним общим.

    Один проход одним регэкспом по всему тексту: это и есть та самая
    единственная проходка, из результата которой строится и подсветка по
    типу, и навигация по изменениям — раньше текст сканировался дважды,
    разными механизмами, с расходящимися результатами.

    >>> typed_value_spans("src=10.0.0.1", {"10.0.0.1": "IP"})
    [(4, 12, 'IP')]
    """
    if not text:
        return []
    keys = sorted({str(k) for k in types if k}, key=len, reverse=True)
    if not keys:
        return []
    pattern = re.compile("|".join(re.escape(k) for k in keys))
    return [(m.start(), m.end(), types.get(m.group(0), default_type))
            for m in pattern.finditer(text)]


def changed_value_spans(text: str, values: Iterable[str]) -> List[Tuple[int, int]]:
    """Диапазоны (start, end) в символах для каждого вхождения values в text.

    values — ключи mapping_table (для Input, исходные значения) либо
    ключи reverse_mapping (для Output, псевдонимы).

    Длинные значения проверяются первыми: иначе "10.0.0.5" подсветил бы
    начало "10.0.0.50", и диапазон получился бы короче реального
    заменённого значения.

    >>> changed_value_spans("src=10.0.0.1 ok", ["10.0.0.1"])
    [(4, 12)]
    >>> changed_value_spans("no matches here", ["10.0.0.1"])
    []
    """
    if not text:
        return []
    keys = sorted({str(v) for v in values if v}, key=len, reverse=True)
    if not keys:
        return []
    pattern = re.compile("|".join(re.escape(k) for k in keys))
    return merge_spans([(m.start(), m.end()) for m in pattern.finditer(text)])


def _tokenize(text: str) -> Tuple[List[str], List[int]]:
    tokens: List[str] = []
    offsets: List[int] = []
    for match in _TOKEN_RE.finditer(text):
        tokens.append(match.group(0))
        offsets.append(match.start())
    return tokens, offsets


def _trim_span(text: str, start: int, end: int) -> Optional[Tuple[int, int]]:
    """Убирает пробелы по краям диапазона — подсвеченный "хвост" из
    пробелов и переводов строк выглядит как подсветка всей строки, ровно
    та проблема, ради которой этот модуль и переписан."""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return (start, end) if end > start else None


def inline_diff_spans(original: str, cleaned: str,
                     max_tokens: int = MAX_DIFF_TOKENS) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Пословный diff: возвращает (спаны в original, спаны в cleaned).

    Подсвечиваются только изменившиеся токены, а не строки целиком.
    На очень больших текстах (сумма токенов больше max_tokens)
    автоматически падает до построчной гранулярности: difflib
    квадратичен в худшем случае, и на логе в сотни тысяч токенов
    пословное сравнение заблокировало бы GUI-поток надолго.

    >>> inline_diff_spans("user=admin ok", "user=[USER_1] ok")
    ([(5, 10)], [(5, 13)])
    """
    import difflib

    a_tokens, a_offsets = _tokenize(original)
    b_tokens, b_offsets = _tokenize(cleaned)
    if len(a_tokens) + len(b_tokens) > max_tokens:
        return _line_level_spans(original, cleaned)

    left: List[Tuple[int, int]] = []
    right: List[Tuple[int, int]] = []
    matcher = difflib.SequenceMatcher(None, a_tokens, b_tokens, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if i2 > i1:
            span = _trim_span(original, a_offsets[i1], a_offsets[i2 - 1] + len(a_tokens[i2 - 1]))
            if span:
                left.append(span)
        if j2 > j1:
            span = _trim_span(cleaned, b_offsets[j1], b_offsets[j2 - 1] + len(b_tokens[j2 - 1]))
            if span:
                right.append(span)
    return merge_spans(left, gap=1), merge_spans(right, gap=1)


def _line_level_spans(original: str, cleaned: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Грубый фолбэк для очень больших текстов: диапазон = вся строка."""
    left_numbers, right_numbers = changed_line_numbers(original, cleaned)
    return (_spans_for_lines(original, left_numbers),
            _spans_for_lines(cleaned, right_numbers))


def _spans_for_lines(text: str, line_numbers: Iterable[int]) -> List[Tuple[int, int]]:
    if not line_numbers:
        return []
    starts = [0]
    for line in text.split("\n")[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    lines = text.split("\n")
    spans = []
    for number in line_numbers:
        idx = number - 1
        if 0 <= idx < len(lines):
            span = _trim_span(text, starts[idx], starts[idx] + len(lines[idx]))
            if span:
                spans.append(span)
    return merge_spans(spans)


# ----------------------------------------------------------------------
# Горячие клавиши
# ----------------------------------------------------------------------
#
# Таблица живёт здесь, а не в gui.py, чтобы (а) её можно было проверить
# тестами без tkinter и (б) справка по хоткеям и сами биндинги строились
# из ОДНОГО источника — иначе они неизбежно разъезжаются.

HOTKEYS: List[Tuple[str, str, str]] = [
    # (accelerator для меню, имя метода GUI, описание для справки)
    ("Ctrl+O", "open_file", "Открыть файл лога"),
    ("Ctrl+S", "save_file", "Сохранить результат"),
    ("Ctrl+Shift+C", "copy_result", "Скопировать результат в буфер обмена"),
    ("Ctrl+Enter", "start_processing_thread", "Анонимизировать"),
    ("Ctrl+D", "deanonymize_text", "Де-анонимизировать текст из левого окна"),
    # Не Ctrl+Z: tk.Text создан с undo=True, и Ctrl+Z пользователь ждёт
    # для отката СВОЕГО набора текста, а не операции анонимизации.
    ("Ctrl+Alt+Z", "undo_last", "Отменить последнюю операцию анонимизации"),
    ("Ctrl+L", "clear_all", "Очистить оба окна и таблицу соответствия"),
    ("Ctrl+Shift+L", "clear_focused_pane", "Очистить только активное окно"),
    ("Ctrl+F", "_focus_log_search", "Поиск по логам"),
    ("F3", "_find_next", "Следующее совпадение"),
    ("Shift+F3", "_find_previous", "Предыдущее совпадение"),
    ("Ctrl+Alt+Down", "_next_diff", "Следующее изменение"),
    ("Ctrl+Alt+Up", "_previous_diff", "Предыдущее изменение"),
    ("Escape", "cancel_operation", "Отменить текущую обработку"),
    ("F1", "show_shortcuts", "Показать эту справку"),
]


def accelerator_to_sequence(accelerator: str) -> str:
    """'Ctrl+Shift+L' -> '<Control-Shift-L>' (формат биндингов Tk).

    Регистр буквы значим: Tk различает <Control-l> и <Control-L> —
    второе означает Ctrl+Shift+L. Поэтому одиночная буква приводится к
    нижнему регистру, а при наличии Shift — к верхнему.

    >>> accelerator_to_sequence("Ctrl+O")
    '<Control-o>'
    >>> accelerator_to_sequence("Ctrl+Shift+L")
    '<Control-Shift-L>'
    >>> accelerator_to_sequence("F1")
    '<F1>'
    """
    parts = [p.strip() for p in accelerator.split("+") if p.strip()]
    has_shift = any(p.lower() == "shift" for p in parts)
    converted = []
    for part in parts:
        low = part.lower()
        if low == "ctrl":
            converted.append("Control")
        elif low == "shift":
            converted.append("Shift")
        elif low == "alt":
            converted.append("Alt")
        elif low == "enter":
            converted.append("Return")
        elif len(part) == 1 and part.isalpha():
            converted.append(part.upper() if has_shift else part.lower())
        else:
            converted.append(part)
    return "<" + "-".join(converted) + ">"


def format_shortcuts_help() -> str:
    """Человекочитаемая справка по хоткеям (окно по F1)."""
    width = max(len(acc) for acc, _, _ in HOTKEYS)
    return "\n".join(f"{acc.ljust(width)}   {description}" for acc, _, description in HOTKEYS)


# Раскладка ЙЦУКЕН: Tk отдаёт keysym кириллической буквы, и биндинг
# <Control-l> просто не срабатывает при русской раскладке — типовая
# жалоба на tkinter-приложения. Приводим keysym к латинской букве на
# той же физической клавише.
_JCUKEN_TO_QWERTY = {
    "й": "q", "ц": "w", "у": "e", "к": "r", "е": "t", "н": "y", "г": "u",
    "ш": "i", "щ": "o", "з": "p", "х": "[", "ъ": "]",
    "ф": "a", "ы": "s", "в": "d", "а": "f", "п": "g", "р": "h", "о": "j",
    "л": "k", "д": "l", "ж": ";", "э": "'",
    "я": "z", "ч": "x", "с": "c", "м": "v", "и": "b", "т": "n", "ь": "m",
    "б": ",", "ю": ".", "ё": "`",
}

_CYRILLIC_KEYSYM_TO_CHAR = {
    "Cyrillic_a": "а", "Cyrillic_be": "б", "Cyrillic_ve": "в", "Cyrillic_ghe": "г",
    "Cyrillic_de": "д", "Cyrillic_ie": "е", "Cyrillic_io": "ё", "Cyrillic_zhe": "ж",
    "Cyrillic_ze": "з", "Cyrillic_i": "и", "Cyrillic_shorti": "й", "Cyrillic_ka": "к",
    "Cyrillic_el": "л", "Cyrillic_em": "м", "Cyrillic_en": "н", "Cyrillic_o": "о",
    "Cyrillic_pe": "п", "Cyrillic_er": "р", "Cyrillic_es": "с", "Cyrillic_te": "т",
    "Cyrillic_u": "у", "Cyrillic_ef": "ф", "Cyrillic_ha": "х", "Cyrillic_tse": "ц",
    "Cyrillic_che": "ч", "Cyrillic_sha": "ш", "Cyrillic_shcha": "щ",
    "Cyrillic_hardsign": "ъ", "Cyrillic_yeru": "ы", "Cyrillic_softsign": "ь",
    "Cyrillic_e": "э", "Cyrillic_yu": "ю", "Cyrillic_ya": "я",
}


def normalize_keysym(keysym: str) -> str:
    """Кириллический keysym -> латинская буква на той же клавише.

    >>> normalize_keysym("Cyrillic_de")
    'l'
    >>> normalize_keysym("o")
    'o'
    """
    if not keysym:
        return ""
    char = _CYRILLIC_KEYSYM_TO_CHAR.get(keysym)
    if char is None and len(keysym) == 1:
        char = keysym.lower()
    if char is None:
        return keysym
    return _JCUKEN_TO_QWERTY.get(char, char)


def truncate_display_text(text: str, limit: int) -> Tuple[str, bool]:
    """Keep GUI rendering bounded while preserving both ends of a large log."""
    if limit <= 0 or len(text) <= limit:
        return text, False
    head = max(1, limit * 2 // 3)
    tail = max(1, limit - head)
    marker = "\n\n[GUI display truncated; full text remains available for processing]\n\n"
    return text[:head] + marker + text[-tail:], True


def format_result_payload(text: str, output_format: str) -> Tuple[str, str]:
    """Serialize GUI output and return (content, recommended extension)."""
    import csv
    import io
    import json

    fmt = str(output_format or "text").lower()
    if fmt == "json":
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2), ".json"
        except (TypeError, ValueError):
            return json.dumps({"text": text}, ensure_ascii=False, indent=2), ".json"
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["line_number", "text"])
        for index, line in enumerate(text.splitlines(), 1):
            writer.writerow([index, line])
        return buffer.getvalue(), ".csv"
    return text, ".log"


def format_scan_report(findings: List[dict], limit: int = 500) -> str:
    """Human-readable scan listing (no masking)."""
    if not findings:
        return "Scan: совпадений не найдено. Лог не изменялся.\n"
    lines = [
        "Scan: что было бы замаскировано (лог не изменялся).",
        f"Всего совпадений: {len(findings)}",
        "",
    ]
    for item in findings[:limit]:
        lines.append(f"L{item.get('line', '?')}\t{item.get('type', '')}\t{item.get('value', '')}")
    if len(findings) > limit:
        lines.append(f"... ещё {len(findings) - limit}")
    return "\n".join(lines) + "\n"


def mapping_rows_filtered(mapping: Dict[str, str], query: str, type_filter: str,
                          type_of) -> List[Tuple[str, str]]:
    q = (query or "").strip().lower()
    tf = (type_filter or "").strip().upper()
    if tf in ("", "ALL", "ВСЕ", "ВСЕ ТИПЫ"):
        tf = ""
    rows = []
    for orig, pseudo in mapping.items():
        if tf and type_of(pseudo) != tf:
            continue
        if q and q not in orig.lower() and q not in pseudo.lower():
            continue
        rows.append((orig, pseudo))
    return rows
