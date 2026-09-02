"""
Логика GUI, вынесенная в модуль БЕЗ импорта tkinter.

Смысл вынесения: gui.py импортирует tkinter на уровне модуля, поэтому
в окружениях без установленного Tk (часто встречается на серверах/CI)
даже просто `import soc_log_anonymizer.gui` упадёт с ImportError, и
протестировать логику формирования текста статуса, вычисления прогресса
и т.п. становится невозможно. Все функции здесь — чистые (без побочных
эффектов и без зависимости от tkinter), поэтому их можно тестировать
`unittest`-ом в любом окружении — см. tests/test_gui_logic.py.
"""

from typing import List, Optional, Tuple

MIN_SALT_LEN = 16  # символов; менее — предупреждение об энтропии соли


def salt_entropy_warning(salt: str) -> Optional[str]:
    """Простая эвристика: предупреждает о короткой/малоразнообразной соли.
    Возвращает текст предупреждения или None, если соль выглядит разумно."""
    if len(salt) < MIN_SALT_LEN:
        return (f"Соль короче {MIN_SALT_LEN} символов ({len(salt)}). "
                f"Рекомендуется минимум 32 hex-символа (16 байт), чтобы затруднить "
                f"словарную атаку на таблицу соответствия.")
    if len(set(salt)) < 6:
        return "Соль имеет низкое разнообразие символов — похоже на неслучайную строку."
    return None


def format_result_status(is_safe: bool, issues: List[str]) -> Tuple[str, str]:
    """Формирует (текст, вид_чипа) для статус-лейбла по результату verify().
    "Вид" соответствует ttk-стилю Status{Kind}.TLabel в gui.py."""
    if is_safe:
        return "Безопасно для LLM", "Success"
    first_issue = issues[0] if issues else "Неизвестный риск"
    extra = f" (+{len(issues) - 1})" if len(issues) > 1 else ""
    return f"Ошибка: {first_issue}{extra}", "Danger"


def compute_progress_pct(done: int, total: int) -> int:
    """Процент выполнения для прогресс-бара, безопасно для total<=0."""
    if total <= 0:
        return 100
    pct = int(done / total * 100)
    return max(0, min(100, pct))


def status_style_name(kind: str) -> str:
    """Имя ttk-стиля статус-чипа по короткому обозначению вида ("Success",
    "danger", ...) — регистр не важен."""
    return f"Status{kind.capitalize()}.TLabel"


def format_size_warning(size_mb: float, limit_mb: int) -> str:
    """Текст предупреждения о том, что файл превышает порог размера,
    рекомендованный для полной загрузки в память (не через --stream)."""
    return (f"Выбранный файл имеет размер {size_mb:.1f} МБ, что превышает "
            f"рекомендованный порог {limit_mb} МБ для загрузки целиком в память. "
            f"Это может привести к заметному замедлению интерфейса или нехватке памяти "
            f"на очень больших файлах.")


def find_context_snippet(text: str, value: str, radius: int = 40) -> str:
    """Находит первое вхождение `value` в `text` и возвращает окружающий
    фрагмент — используется для тултипа в таблице соответствия (показать,
    в каком контексте встретилось исходное значение)."""
    if not value:
        return "(пустое значение)"
    idx = text.find(value)
    if idx == -1:
        return "(контекст не найден в текущем тексте ввода)"
    start = max(0, idx - radius)
    end = min(len(text), idx + len(value) + radius)
    snippet = text[start:end].replace("\n", " ").replace("\t", " ")
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"
