"""Public result object for anonymize_result()."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AnonymizeResult:
    """Snapshot of one anonymize pass.

    `text` is the masked document. `stats` counts replacements by type.
    `mapping` is original -> pseudonym. `issues` come from verify().
    """

    text: str
    stats: dict[str, int] = field(default_factory=dict)
    mapping: dict[str, str] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    safe: bool = True
    metrics: dict[str, int] = field(default_factory=dict)
