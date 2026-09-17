"""Registry of maskable types, families, and quality filters.

Structural tags (CEF_KV, SECRET, USER_FIELD, …) still run so values can
be classified; `_hash_val` then respects allowlist.
Vendor-specific *profiles* are intentionally out of scope.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Public detector families (documentation / UI filters).
MASKABLE_FAMILIES = (
    "IP", "EMAIL", "USER", "FQDN", "ORG", "SID", "UUID", "MAC", "PHONE",
    "HASH", "JWT", "SECRET", "URL", "TOKEN",
    "UNP", "PAN", "IBAN", "BY_ID",
)

TAG_FAMILY: dict[str, str] = {
    "IP": "IP",
    "IP_NET": "IP",
    "EMAIL": "EMAIL",
    "USER": "USER",
    "USER_FIELD": "USER",
    "AUTH_USER": "USER",
    "AUTH_USER_CISCO": "USER",
    "AUTH_USER_SU_FROM": "USER",
    "AUTH_USER_SUDO": "USER",
    "AUTH_USER_WIN": "USER",
    "USER_PATH": "USER",
    "FQDN": "FQDN",
    "ORG": "ORG",
    "SID": "SID",
    "UUID": "UUID",
    "MAC": "MAC",
    "PHONE": "PHONE",
    "HASH": "HASH",
    "JWT": "JWT",
    "SECRET": "SECRET",
    "TOKEN": "SECRET",
    "CLOUD_SECRET": "SECRET",
    "SSH_KEY": "SECRET",
    "CONN_STR": "SECRET",
    "BASE64_CMD": "SECRET",
    "B64_CMD": "SECRET",
    "URL": "URL",
    "CEF_KV": "CEF_KV",
    "SENSITIVE": "SECRET",
    "UNP": "UNP",
    "PAN": "PAN",
    "CARD": "PAN",
    "IBAN": "IBAN",
    "BY_ID": "BY_ID",
}

# Extractor tags always applied (values still filtered in _hash_val).
STRUCTURAL_TAGS = frozenset({
    "CEF_KV", "SECRET", "USER_FIELD", "AUTH_USER", "AUTH_USER_CISCO",
    "AUTH_USER_SU_FROM", "AUTH_USER_SUDO", "AUTH_USER_WIN", "USER_PATH", "BASE64_CMD",
})

DEFAULT_FQDN_STOPWORDS = frozenset({
    "a", "an", "the", "for", "from", "with", "this", "that", "not", "and",
    "or", "but", "all", "any", "new", "old", "get", "set", "put", "use",
    "via", "per", "see", "info", "report", "file", "data", "test", "true",
    "false", "none", "null", "type", "name", "src", "dst", "to", "in",
    "on", "at", "by", "of", "as", "is", "be", "no", "ok", "id",
})

PATHISH_USER_DOMAINS = frozenset({
    "windows", "system32", "syswow64", "users", "program", "files",
    "appdata", "temp", "tmp", "winnt", "drivers", "driver", "programfiles",
    "documents", "downloads", "desktop",
})

HASH_CONTEXT_RE = re.compile(
    r"(?i)(?:hash|md5|sha-?1|sha-?256|sha-?512|ntlm|digest|checksum|thumbprint|fingerprint)"
)

_HEX_LETTER_RE = re.compile(r"[A-Fa-f]")


def family_for_tag(tag: str) -> str:
    if tag.startswith("CUSTOM:"):
        return "CUSTOM"
    return TAG_FAMILY.get(tag, tag)


def is_allowlisted(value: str, allowlist: Iterable[str]) -> bool:
    needle = value.strip()
    if not needle:
        return False
    lowered = needle.lower()
    for item in allowlist:
        item = str(item).strip()
        if not item:
            continue
        if needle == item or lowered == item.lower():
            return True
    return False


def hash_looks_like_id(value: str) -> bool:
    """True when a hex blob is too uniform to be a useful hash match."""
    compact = value.strip()
    if not compact:
        return True
    if compact.isdigit():
        return True
    if len(set(compact.lower())) < 4:
        return True
    if not _HEX_LETTER_RE.search(compact):
        return True
    return False


def hash_has_context(text: str, start: int, end: int, radius: int = 48) -> bool:
    window = text[max(0, start - radius):min(len(text), end + radius)]
    return bool(HASH_CONTEXT_RE.search(window))


def is_plausible_free_text_hash(value: str, text: str, start: int, end: int,
                                require_context: bool) -> bool:
    if hash_looks_like_id(value):
        return False
    if require_context and not hash_has_context(text, start, end):
        return False
    return True


def is_plausible_fqdn(value: str, stopwords: Iterable[str]) -> bool:
    labels = [part for part in value.split(".") if part]
    if len(labels) < 2:
        return False
    blocked = {str(s).lower() for s in stopwords}
    if labels[0].lower() in blocked:
        return False
    if labels[-1].lower() in blocked and labels[-1].lower() in {"info", "file", "data"}:
        return False
    return True


def is_plausible_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 10 <= len(digits) <= 15


def is_plausible_windows_user(value: str) -> bool:
    if "\\" not in value:
        return False
    domain, _, user = value.partition("\\")
    if len(domain) < 2 or not user:
        return False
    if domain.lower() in PATHISH_USER_DOMAINS:
        return False
    if user.lower() in PATHISH_USER_DOMAINS:
        return False
    return True
