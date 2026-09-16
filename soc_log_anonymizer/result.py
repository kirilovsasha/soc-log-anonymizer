"""Public result object for anonymize_result()."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class AnonymizeResult:
    """Snapshot of one anonymize pass.

    `text` is the masked document. `stats` counts replacements by type.
    `mapping` is original -> pseudonym. `issues` come from verify().
    """

    text: str
    stats: Dict[str, int] = field(default_factory=dict)
    mapping: Dict[str, str] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)
    safe: bool = True
    metrics: Dict[str, int] = field(default_factory=dict)
