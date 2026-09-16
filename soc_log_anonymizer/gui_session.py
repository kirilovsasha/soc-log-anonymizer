"""Persist org / mask_types / skip_types / allowlist between GUI launches."""

from typing import Any, Dict, List


def parse_csv_types(text: str) -> List[str]:
    return [part.strip().upper() for part in (text or "").split(",") if part.strip()]


def parse_csv_values(text: str) -> List[str]:
    return [part.strip() for part in (text or "").split(",") if part.strip()]


def format_csv(values: List[str]) -> str:
    return ", ".join(str(v) for v in values if str(v).strip())


def extract_session_profile(state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "org_name": str(state.get("org_name") or ""),
        "mask_types": list(state.get("mask_types") or []),
        "skip_types": list(state.get("skip_types") or []),
        "allowlist": list(state.get("allowlist") or []),
    }


def session_fields_from_config(org_name: str, mask_types, skip_types, allowlist) -> Dict[str, Any]:
    return {
        "org_name": org_name,
        "mask_types": list(mask_types or []),
        "skip_types": list(skip_types or []),
        "allowlist": list(allowlist or []),
    }
