"""Source log profiles and allowlist helpers (no tkinter).

Profiles only adjust field-name lists and optional allowlist extras —
they do not change the anonymizer core or detector regexes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from .config import (
    AnonymizerConfig,
    _default_cef_fields,
    _default_cef_user_fields,
    _default_secret_field_names,
    _default_sensitive_json_keys,
    _default_user_field_names,
)


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


@dataclass(frozen=True)
class SourceProfile:
    id: str
    title: str
    description: str
    # None = leave current list unchanged; list = replace with this baseline then merge extras.
    reset_to_defaults: bool = False
    user_field_names: Optional[Sequence[str]] = None
    secret_field_names: Optional[Sequence[str]] = None
    cef_fields: Optional[Sequence[str]] = None
    cef_user_fields: Optional[Sequence[str]] = None
    sensitive_json_keys: Optional[Sequence[str]] = None
    allowlist_add: Sequence[str] = field(default_factory=tuple)
    allowlist_preset_ids: Sequence[str] = field(default_factory=tuple)


SOURCE_PROFILES: Dict[str, SourceProfile] = {
    "default": SourceProfile(
        id="default",
        title="По умолчанию",
        description="Встроенные поля user/secret/CEF без дополнительных allowlist.",
        reset_to_defaults=True,
    ),
    "windows": SourceProfile(
        id="windows",
        title="Windows Event",
        description="Subject/Target account fields + встроенные учётки Windows в allowlist.",
        reset_to_defaults=True,
        user_field_names=_default_user_field_names() + [
            "subjectaccountname", "targetusername", "objectaccountname",
            "subjectusername", "targetuser", "membername",
        ],
        sensitive_json_keys=_default_sensitive_json_keys() + [
            "subjectaccountname", "targetusername", "objectaccountname",
            "subjectusername", "membername", "targetdomainname",
        ],
        allowlist_preset_ids=("windows_builtin",),
    ),
    "cisco": SourceProfile(
        id="cisco",
        title="Cisco ASA / IOS",
        description="Поля uname/src_user и ASA key=value без пробелов.",
        reset_to_defaults=True,
        user_field_names=_default_user_field_names() + [
            "uname", "src_user", "dst_user", "user_name",
        ],
        cef_fields=_default_cef_fields() + [
            "src_ip", "dst_ip", "srcip", "dstip", "orig", "peer_gateway",
        ],
        allowlist_add=("enable",),
    ),
    "checkpoint": SourceProfile(
        id="checkpoint",
        title="Checkpoint",
        description="Subject / suser / duser и типичные SmartCenter-поля.",
        reset_to_defaults=True,
        user_field_names=_default_user_field_names() + [
            "subject", "src_user", "dst_user", "administrator",
        ],
        cef_fields=_default_cef_fields() + ["origin", "orig"],
        cef_user_fields=_default_cef_user_fields() + ["suser", "duser"],
    ),
    "syslog": SourceProfile(
        id="syslog",
        title="Syslog / auth",
        description="sshd/su auth конструкции и стандартные user/password поля.",
        reset_to_defaults=True,
        user_field_names=_default_user_field_names() + [
            "ruser", "rhost", "logname",
        ],
        secret_field_names=_default_secret_field_names() + ["pam_unix"],
        allowlist_preset_ids=("dns_public",),
    ),
}


def profile_choices() -> List[tuple]:
    """(id, title) pairs for combobox, stable order."""
    order = ("default", "windows", "cisco", "checkpoint", "syslog")
    return [(pid, SOURCE_PROFILES[pid].title) for pid in order if pid in SOURCE_PROFILES]


def allowlist_from_presets(preset_ids: Iterable[str]) -> List[str]:
    values: List[str] = []
    for pid in preset_ids:
        values.extend(ALLOWLIST_PRESETS.get(pid, []))
    return _uniq(values)


def apply_source_profile(config: AnonymizerConfig, profile_id: str) -> AnonymizerConfig:
    """Apply profile overlays onto config (mutates and returns the same instance)."""
    profile = SOURCE_PROFILES.get(profile_id)
    if profile is None:
        raise KeyError(f"Unknown source profile: {profile_id}")

    if profile.reset_to_defaults:
        config.user_field_names = list(_default_user_field_names())
        config.secret_field_names = list(_default_secret_field_names())
        config.cef_fields = list(_default_cef_fields())
        config.cef_user_fields = list(_default_cef_user_fields())
        config.sensitive_json_keys = list(_default_sensitive_json_keys())

    if profile.user_field_names is not None:
        config.user_field_names = merge_lists(config.user_field_names, profile.user_field_names)
    if profile.secret_field_names is not None:
        config.secret_field_names = merge_lists(config.secret_field_names, profile.secret_field_names)
    if profile.cef_fields is not None:
        config.cef_fields = merge_lists(config.cef_fields, profile.cef_fields)
    if profile.cef_user_fields is not None:
        config.cef_user_fields = merge_lists(config.cef_user_fields, profile.cef_user_fields)
    if profile.sensitive_json_keys is not None:
        config.sensitive_json_keys = merge_lists(config.sensitive_json_keys, profile.sensitive_json_keys)

    extras = list(profile.allowlist_add) + allowlist_from_presets(profile.allowlist_preset_ids)
    if extras:
        config.allowlist = merge_lists(config.allowlist, extras)

    return config.normalize_keys()


def parse_allowlist_lines(text: str) -> List[str]:
    """One value per line; commas also split for convenience."""
    values: List[str] = []
    for line in (text or "").splitlines():
        for part in line.split(","):
            values.append(part)
    return _uniq(values)


def format_allowlist_lines(values: Iterable[str]) -> str:
    return "\n".join(_uniq(values))
