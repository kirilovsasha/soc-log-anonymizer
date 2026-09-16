"""Deterministic merge of parallel-worker mapping tables."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Mapping, MutableMapping, Tuple


def parse_pseudo(pseudo: str) -> Tuple[str, str, int]:
    """Return ``(prefix, hash_hex, suffix)``; suffix 1 means no numeric suffix.

    Pseudonyms look like ``[USER_a1b2c3d4e5f6]`` or ``[USER_a1b2c3d4e5f6_2]``.
    Prefix may contain underscores / colons (``CUSTOM:NAME``).
    """
    if not (isinstance(pseudo, str) and pseudo.startswith("[") and pseudo.endswith("]")):
        return "VALUE", str(pseudo), 1
    inner = pseudo[1:-1]
    parts = inner.rsplit("_", 2)
    if (
        len(parts) == 3
        and parts[-1].isdigit()
        and parts[-2]
        and all(c in "0123456789abcdefABCDEF" for c in parts[-2])
    ):
        return parts[0], parts[1], int(parts[2])
    if len(parts) >= 2 and parts[-1] and all(c in "0123456789abcdefABCDEF" for c in parts[-1]):
        return "_".join(parts[:-1]), parts[-1], 1
    return "VALUE", pseudo, 1


def base_pseudo(prefix: str, hash_hex: str) -> str:
    return f"[{prefix}_{hash_hex}]"


def merge_mappings_deterministic(
    mappings: Iterable[Mapping[str, str]],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Merge worker ``original -> pseudo`` maps with stable collision suffixes.

    Collision groups (same prefix+hash, different originals) are ordered by
    ``original`` string so every parent process assigns the same suffixes
    regardless of worker completion order.
    """
    groups: Dict[Tuple[str, str], List[str]] = {}
    for mapping in mappings:
        for original, pseudo in mapping.items():
            prefix, hash_hex, _suffix = parse_pseudo(pseudo)
            key = (prefix, hash_hex)
            bucket = groups.setdefault(key, [])
            if original not in bucket:
                bucket.append(original)

    canonical: Dict[str, str] = {}
    reverse: Dict[str, str] = {}
    for (prefix, hash_hex), originals in groups.items():
        ordered = sorted(originals)
        for index, original in enumerate(ordered):
            if index == 0:
                pseudo = base_pseudo(prefix, hash_hex)
            else:
                # Match _hash_val: first collision uses suffix 2 (not 1).
                pseudo = f"[{prefix}_{hash_hex}_{index + 1}]"
            canonical[original] = pseudo
            reverse[pseudo] = original
    return canonical, reverse


def build_pseudo_rewrite(
    worker_mappings: Iterable[Mapping[str, str]],
    canonical: Mapping[str, str],
) -> Dict[str, str]:
    """Map each worker-emitted pseudo onto the canonical pseudo for that original."""
    rewrite: Dict[str, str] = {}
    for mapping in worker_mappings:
        for original, old_pseudo in mapping.items():
            new_pseudo = canonical.get(original)
            if new_pseudo and old_pseudo != new_pseudo:
                rewrite[old_pseudo] = new_pseudo
    return rewrite


def apply_pseudo_rewrite(text: str, rewrite: Mapping[str, str]) -> str:
    if not rewrite or not text:
        return text
    ordered = sorted(rewrite.keys(), key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(p) for p in ordered))
    return pattern.sub(lambda m: rewrite[m.group(0)], text)


def install_merged_mapping(
    target: MutableMapping[str, str],
    reverse_target: MutableMapping[str, str],
    canonical: Mapping[str, str],
    reverse: Mapping[str, str],
) -> None:
    target.clear()
    reverse_target.clear()
    target.update(canonical)
    reverse_target.update(reverse)
