"""Belarus-oriented PII validators and residual-scan heuristics.

Used by built-in UNP / PAN / IBAN / personal-id detectors and by
``residual_scan`` after anonymization. Stdlib only.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

# Official BY UNP weights (positions 1..8). Check digit = sum % 11; 10 → invalid.
_UNP_WEIGHTS = (29, 23, 19, 17, 13, 7, 5, 3)
_UNP_LETTER_VALUE = {
    "A": 10, "B": 11, "C": 12, "E": 13, "H": 14,
    "K": 15, "M": 16, "O": 17, "P": 18, "T": 19,
}
_UNP_ALPHA = frozenset("ABCEHKMOPT")

# Visa/MC/Amex/MIR test-friendly compact digit run (spaces/dashes stripped later).
PAN_RE = re.compile(
    r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"
)
UNP_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9]|[ABCEHKMOPT])(?:[0-9]|[ABCEHKMOPT])\d{7}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# Citizen personal / identification number (14 chars): 7 digits + letter + 3 digits + 2 letters + digit.
BY_PERSONAL_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])\d{7}[A-Za-z]\d{3}[A-Za-z]{2}\d(?![A-Za-z0-9])"
)
IBAN_BY_RE = re.compile(
    r"\bBY\d{2}[A-Z0-9]{24}\b",
    re.IGNORECASE,
)

# Residual heuristics (post-mask).
_PSEUDO_RE = re.compile(r"\[[A-Z][A-Z0-9_]{1,40}\]")
_EMAIL_LIKE_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_USER_RE = re.compile(r"(?<![\\])\b[A-Za-z0-9_-]{2,}\\[A-Za-z0-9._-]{1,}\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*")
_PHONE_BY_RE = re.compile(
    r"(?:\+375|80(?:29|33|44|25|17))\s*\(?\d{2,3}\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}\b"
)
_LONG_DIGIT_RE = re.compile(r"(?<!\d)\d{12,19}(?!\d)")


def _unp_char_value(ch: str) -> Optional[int]:
    if ch.isdigit():
        return int(ch)
    return _UNP_LETTER_VALUE.get(ch.upper())


def is_valid_unp(value: str) -> bool:
    """Return True when *value* is a structurally valid Belarus UNP."""
    raw = value.strip().upper()
    if raw.startswith("BY") and len(raw) == 11:
        raw = raw[2:]
    if len(raw) != 9:
        return False
    body, check_ch = raw[:8], raw[8]
    if not check_ch.isdigit():
        return False
    # Positions 3–9 must be digits; 1–2 digit or ABCEHKMOPT.
    for i, ch in enumerate(body):
        if i < 2:
            if not (ch.isdigit() or ch in _UNP_ALPHA):
                return False
        elif not ch.isdigit():
            return False
    total = 0
    for ch, weight in zip(body, _UNP_WEIGHTS):
        val = _unp_char_value(ch)
        if val is None:
            return False
        total += val * weight
    remainder = total % 11
    if remainder == 10:
        return False
    return remainder == int(check_ch)


def luhn_ok(value: str) -> bool:
    """Luhn check on digit characters of *value* (ignores spaces/dashes)."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def is_plausible_pan(value: str) -> bool:
    compact = re.sub(r"[^\d]", "", value)
    if len(compact) < 13 or len(compact) > 19:
        return False
    # Reject uniform runs (000…); allow low-diversity test BINs like 4111…1111.
    if len(set(compact)) < 2:
        return False
    return luhn_ok(compact)


def is_plausible_by_personal_id(value: str) -> bool:
    return bool(BY_PERSONAL_ID_RE.fullmatch(value.strip()))


def is_plausible_iban_by(value: str) -> bool:
    raw = value.strip().upper().replace(" ", "")
    if not IBAN_BY_RE.fullmatch(raw):
        return False
    # ISO 13616 mod-97 check (optional but cuts FP).
    rearranged = raw[4:] + raw[:4]
    numeric = []
    for ch in rearranged:
        if ch.isdigit():
            numeric.append(ch)
        elif "A" <= ch <= "Z":
            numeric.append(str(ord(ch) - 55))
        else:
            return False
    try:
        return int("".join(numeric)) % 97 == 1
    except ValueError:
        return False


def pan_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


ResidualFinding = Tuple[str, str]  # (kind, sample)


def residual_scan(
    text: str,
    *,
    allowlist: Iterable[str] = (),
    min_digit_run: int = 12,
) -> List[ResidualFinding]:
    """Heuristic leftover PII scan on already-anonymized text.

    Findings are warnings for gatekeeper / quality report — they intentionally
    overlap built-in regex verify so unknown formats still raise risk.
    """
    if not text:
        return []
    allow = {str(x).strip().lower() for x in allowlist if str(x).strip()}
    findings: List[ResidualFinding] = []

    def _ok(sample: str) -> bool:
        return sample.strip().lower() not in allow and not _PSEUDO_RE.fullmatch(sample.strip())

    for match in _EMAIL_LIKE_RE.finditer(text):
        sample = match.group(0)
        if _ok(sample):
            findings.append(("EMAIL", sample))

    for match in _DOMAIN_USER_RE.finditer(text):
        sample = match.group(0)
        left = sample.split("\\", 1)[0].lower()
        if left in {"windows", "system32", "users", "program", "files"}:
            continue
        if _ok(sample):
            findings.append(("USER", sample))

    for match in _IPV4_RE.finditer(text):
        sample = match.group(0)
        if _ok(sample):
            findings.append(("IP", sample))

    for match in _JWT_LIKE_RE.finditer(text):
        sample = match.group(0)
        if _ok(sample):
            findings.append(("JWT", sample))

    for match in _PHONE_BY_RE.finditer(text):
        sample = match.group(0)
        if _ok(sample):
            findings.append(("PHONE", sample))

    for match in UNP_RE.finditer(text):
        sample = match.group(0)
        if is_valid_unp(sample) and _ok(sample):
            findings.append(("UNP", sample))

    for match in BY_PERSONAL_ID_RE.finditer(text):
        sample = match.group(0)
        if _ok(sample):
            findings.append(("BY_ID", sample))

    for match in IBAN_BY_RE.finditer(text):
        sample = match.group(0)
        if is_plausible_iban_by(sample) and _ok(sample):
            findings.append(("IBAN", sample))

    digit_re = re.compile(rf"(?<!\d)\d{{{max(12, int(min_digit_run))},19}}(?!\d)")
    for match in digit_re.finditer(text):
        sample = match.group(0)
        if is_plausible_pan(sample) and _ok(sample):
            findings.append(("PAN", sample))

    # Deduplicate by (kind, sample), preserve order.
    seen = set()
    unique: List[ResidualFinding] = []
    for item in findings:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def residual_risk_score(findings: List[ResidualFinding]) -> int:
    """Simple 0–100 score for GUI / CLI summaries."""
    if not findings:
        return 0
    weights = {
        "JWT": 25, "SECRET": 25, "PAN": 20, "IBAN": 20, "UNP": 18,
        "BY_ID": 18, "EMAIL": 12, "USER": 12, "PHONE": 10, "IP": 8,
    }
    score = sum(weights.get(kind, 10) for kind, _ in findings)
    return min(100, score)
