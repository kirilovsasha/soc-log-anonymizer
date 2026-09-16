"""Lightweight CEF / LEEF / RFC5424 splitting (not vendor profiles)."""

from __future__ import annotations

import re
from typing import Callable, List, Optional, Tuple

_CEF_RE = re.compile(
    r"^(?P<prefix>.*?)(?P<head>CEF:\d+(?:\|[^|]*){6})\|(?P<ext>.*)$"
)
_LEEF_RE = re.compile(
    r"^(?P<prefix>.*?)(?P<head>LEEF:\d+(?:\.\d+)?(?:\|[^|]*){4})\|(?P<ext>.*)$",
    re.IGNORECASE,
)
_RFC5424_RE = re.compile(
    r"^(?P<pri><\d+>\d+\s+\S+\s+)(?P<host>\S+)(?P<rest>\s+.*)$"
)


def join_continued_lines(text: str) -> str:
    """Join syslog backslash continuations and indented stack-trace lines."""
    if not text:
        return text
    lines = text.splitlines(keepends=True)
    if len(lines) <= 1:
        return text
    out: List[str] = []
    buf = ""
    buf_nl = ""
    for line in lines:
        nl = ""
        body = line
        if body.endswith("\r\n"):
            nl = "\r\n"
            body = body[:-2]
        elif body.endswith("\n"):
            nl = "\n"
            body = body[:-1]
        if buf:
            if buf.endswith("\\"):
                left = buf[:-1]
                right = body.lstrip()
                glue = " " if left and right and not left[-1].isspace() else ""
                buf = left + glue + right
                buf_nl = nl or buf_nl
                continue
            if body[:1] in " \t":
                buf = buf + " " + body.lstrip()
                buf_nl = nl or buf_nl
                continue
            out.append(buf + (buf_nl or "\n"))
            buf = body
            buf_nl = nl
        else:
            buf = body
            buf_nl = nl
    if buf or buf_nl:
        out.append(buf + buf_nl)
    return "".join(out)


def parse_cef(line: str) -> Optional[Tuple[str, str, str]]:
    match = _CEF_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    return match.group("prefix"), match.group("head"), match.group("ext")


def parse_leef(line: str) -> Optional[Tuple[str, str, str]]:
    match = _LEEF_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    return match.group("prefix"), match.group("head"), match.group("ext")


def parse_rfc5424_host(line: str) -> Optional[Tuple[str, str, str]]:
    match = _RFC5424_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    return match.group("pri"), match.group("host"), match.group("rest")


def mask_structured_line(line: str, mask_value: Callable[[str], str]) -> str:
    """Mask RFC5424 hostname. CEF/LEEF stay for CEF_KV to avoid double hashing."""
    trailing = ""
    if line.endswith("\r\n"):
        trailing = "\r\n"
        core = line[:-2]
    elif line.endswith("\n"):
        trailing = "\n"
        core = line[:-1]
    else:
        core = line

    syslog = parse_rfc5424_host(core)
    if syslog:
        pri, host, rest = syslog
        return f"{pri}{mask_value(host)}{rest}" + trailing
    return line
