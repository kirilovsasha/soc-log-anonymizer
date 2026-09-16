"""Theme constants and pseudonym-type colors for the GUI (no tkinter)."""

from typing import Dict, Tuple

PALETTE_LIGHT = {
    "bg": "#eef0f4", "surface": "#ffffff", "surface_alt": "#f5f6fa", "border": "#e1e4ea",
    "text": "#1f2430", "text_secondary": "#6b7280",
    "accent": "#4f46e5", "accent_hover": "#4338ca", "accent_fg": "#ffffff",
    "purple": "#7c3aed", "purple_hover": "#6d28d9",
    "success": "#16a34a", "danger": "#dc2626", "danger_hover": "#b91c1c",
    "warning": "#d97706", "warning_fg": "#3a2a06",
    "input_bg": "#ffffff", "input_fg": "#1f2430",
    "highlight_bg": "#e0e7ff", "highlight_fg": "#3730a3",
    "disabled_bg": "#e5e7eb", "disabled_fg": "#9ca3af",
}

PALETTE_DARK = {
    "bg": "#14161c", "surface": "#1c1f27", "surface_alt": "#20242e", "border": "#2b2f3a",
    "text": "#e5e7eb", "text_secondary": "#9aa0ac",
    "accent": "#6366f1", "accent_hover": "#818cf8", "accent_fg": "#ffffff",
    "purple": "#a78bfa", "purple_hover": "#c4b5fd",
    "success": "#22c55e", "danger": "#f87171", "danger_hover": "#fca5a5",
    "warning": "#fbbf24", "warning_fg": "#3a2a06",
    "input_bg": "#20242e", "input_fg": "#e5e7eb",
    "highlight_bg": "#312e81", "highlight_fg": "#c7d2fe",
    "disabled_bg": "#2b2f3a", "disabled_fg": "#6b7280",
}

TAG_COLORS_LIGHT: Dict[str, Tuple[str, str]] = {
    "IP":      ("#dbeafe", "#1e40af"),
    "IP_NET":  ("#c7d2fe", "#3730a3"),
    "EMAIL":   ("#dcfce7", "#166534"),
    "USER":    ("#fef9c3", "#854d0e"),
    "FQDN":    ("#ffedd5", "#9a3412"),
    "ORG":     ("#fae8ff", "#86198f"),
    "SID":     ("#e0f2fe", "#075985"),
    "UUID":    ("#f3e8ff", "#6b21a8"),
    "MAC":     ("#fce7f3", "#9d174d"),
    "PHONE":   ("#ccfbf1", "#115e59"),
    "HASH":    ("#e5e7eb", "#374151"),
    "JWT":     ("#fee2e2", "#991b1b"),
    "SECRET":  ("#fecaca", "#7f1d1d"),
    "B64_CMD": ("#fed7aa", "#7c2d12"),
    "VALUE":   ("#e0e7ff", "#3730a3"),
}

TAG_COLORS_DARK: Dict[str, Tuple[str, str]] = {
    "IP":      ("#1e3a8a", "#bfdbfe"),
    "IP_NET":  ("#312e81", "#c7d2fe"),
    "EMAIL":   ("#14532d", "#bbf7d0"),
    "USER":    ("#713f12", "#fef08a"),
    "FQDN":    ("#7c2d12", "#fed7aa"),
    "ORG":     ("#701a75", "#f5d0fe"),
    "SID":     ("#0c4a6e", "#bae6fd"),
    "UUID":    ("#581c87", "#e9d5ff"),
    "MAC":     ("#831843", "#fbcfe8"),
    "PHONE":   ("#134e4a", "#99f6e4"),
    "HASH":    ("#374151", "#e5e7eb"),
    "JWT":     ("#7f1d1d", "#fecaca"),
    "SECRET":  ("#7f1d1d", "#fca5a5"),
    "B64_CMD": ("#7c2d12", "#fdba74"),
    "VALUE":   ("#312e81", "#c7d2fe"),
}

_PSEUDONYM_TYPE_PREFIXES = sorted(TAG_COLORS_LIGHT.keys(), key=len, reverse=True)

_TYPE_LEGEND_RU = {
    "IP":      ("IP-адрес", "отдельный IPv4- или IPv6-адрес, например 10.0.0.5"),
    "IP_NET":  ("IP-адрес с подсетью/портом", "запись вида 10.0.0.0/24 или адрес с портом"),
    "EMAIL":   ("Email-адрес", "например jdoe@example.com"),
    "FQDN":    ("Хост / домен (FQDN)", "полное доменное имя, например db01.example.com"),
    "USER":    ("Пользователь / логин", "имя пользователя, Windows-логин DOMAIN\\user или путь к профилю"),
    "ORG":     ("Название организации", "название компании из настроек анонимизации (org_name/org_aliases)"),
    "SID":     ("Windows SID", "идентификатор безопасности вида S-1-5-21-..."),
    "UUID":    ("UUID / GUID", "уникальный идентификатор вида 6ba7b810-9dad-..."),
    "MAC":     ("MAC-адрес", "аппаратный адрес сетевого интерфейса"),
    "PHONE":   ("Номер телефона", "телефонный номер с одним из настроенных префиксов"),
    "HASH":    ("Хэш", "MD5/SHA1/SHA256/NTLM-хэш рядом с hash/md5/sha/ntlm"),
    "JWT":     ("JWT-токен", "токен вида eyJhbGci..."),
    "SECRET":  ("Секрет / пароль", "значение поля password=/token=/secret= и т.п."),
    "B64_CMD": ("Base64-команда", "закодированная команда PowerShell (-enc ...)"),
    "VALUE":   ("Прочее чувствительное значение", "значение, не подошедшее ни под один более специфичный тип"),
}

HIGHLIGHT_TAG_NAMES = [f"hl_{t}" for t in TAG_COLORS_LIGHT]


def pseudonym_type(pseudo: str) -> str:
    """'[EMAIL_ab12cd34ef56]' -> 'EMAIL'. Unknown prefixes -> 'VALUE'."""
    inner = pseudo.strip("[]")
    for prefix in _PSEUDONYM_TYPE_PREFIXES:
        if inner == prefix or inner.startswith(prefix + "_"):
            return prefix
    return "VALUE"
