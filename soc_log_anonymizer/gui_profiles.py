"""Allowlist helpers for the GUI (no tkinter)."""

from __future__ import annotations

from typing import Dict, Iterable, List

from .config import coerce_text_list


def _uniq(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for raw in values:
        item = str(raw).strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def merge_lists(*groups: Iterable[str]) -> List[str]:
    merged: List[str] = []
    for group in groups:
        merged.extend(group)
    return _uniq(merged)


ALLOWLIST_PRESETS: Dict[str, List[str]] = {
    "dns_public": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"],
    "windows_builtin": [
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
        "Administrator", "Administrators", "Everyone",
    ],
}


def allowlist_from_presets(preset_ids: Iterable[str]) -> List[str]:
    values: List[str] = []
    for pid in preset_ids:
        values.extend(ALLOWLIST_PRESETS.get(pid, []))
    return _uniq(values)


def parse_allowlist_lines(text: str) -> List[str]:
    """One value per line; commas also split for convenience."""
    return _uniq(coerce_text_list(text))


def format_allowlist_lines(values: Iterable[str]) -> str:
    return "\n".join(_uniq(values))
