"""Incremental JSON document assembly for streaming anonymization."""

from __future__ import annotations

import json
from typing import Iterator, List, Optional, Tuple


def iter_json_or_text_chunks(lines: Iterator[str]) -> Iterator[Tuple[str, str]]:
    """Yield ``(kind, text)`` where kind is ``json`` or ``text``.

    Accumulates brace/bracket-balanced pretty-printed JSON across lines.
    Non-JSON lines (and incomplete trailing buffers flushed as text) use
    ``text``. Preserves original line endings on text chunks; JSON chunks
    are the raw accumulated source (including newlines) so callers can
    preserve formatting via ``json.dumps(..., indent=2)``.
    """
    decoder = json.JSONDecoder()
    buf = ""
    for line in lines:
        stripped = line.lstrip()
        if not buf:
            if not stripped or stripped[0] not in "{[":
                yield "text", line
                continue
            buf = line
        else:
            buf += line

        while True:
            candidate = buf.lstrip(" \t\r\n")
            if not candidate:
                buf = ""
                break
            if candidate[0] not in "{[":
                # Leading non-JSON after a completed document — emit as text.
                # Find how much whitespace we skipped then emit rest line-wise.
                ws_len = len(buf) - len(buf.lstrip(" \t\r\n"))
                if ws_len:
                    yield "text", buf[:ws_len]
                    buf = buf[ws_len:]
                # Emit until next JSON start or end
                next_json = -1
                for i, ch in enumerate(buf):
                    if ch in "{[":
                        next_json = i
                        break
                if next_json < 0:
                    yield "text", buf
                    buf = ""
                    break
                if next_json > 0:
                    yield "text", buf[:next_json]
                    buf = buf[next_json:]
                continue
            try:
                _obj, end = decoder.raw_decode(candidate)
            except json.JSONDecodeError:
                break
            # Map end index back into buf (account for leading whitespace stripped)
            lead = len(buf) - len(candidate)
            abs_end = lead + end
            chunk = buf[:abs_end]
            yield "json", chunk
            buf = buf[abs_end:]
            # Keep going in case multiple JSON values share a buffer

    if buf:
        # Incomplete JSON — fall back to line-oriented text so we never drop data.
        for piece in _split_keepends(buf):
            yield "text", piece


def _split_keepends(text: str) -> List[str]:
    if not text:
        return []
    parts: List[str] = []
    start = 0
    for i, ch in enumerate(text):
        if ch == "\n":
            parts.append(text[start : i + 1])
            start = i + 1
    if start < len(text):
        parts.append(text[start:])
    return parts


def try_extract_complete_json(text: str) -> Optional[Tuple[object, int]]:
    """Return ``(obj, end_index)`` if ``text`` starts with a complete JSON value."""
    candidate = text.lstrip(" \t\r\n")
    if not candidate or candidate[0] not in "{[":
        return None
    try:
        obj, end = json.JSONDecoder().raw_decode(candidate)
    except json.JSONDecodeError:
        return None
    lead = len(text) - len(candidate)
    return obj, lead + end
