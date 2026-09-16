"""Persist org name between GUI launches."""

from typing import Any, Dict


def extract_session_profile(state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "org_name": str(state.get("org_name") or ""),
    }


def session_fields_from_config(org_name: str) -> Dict[str, Any]:
    return {
        "org_name": org_name,
    }
