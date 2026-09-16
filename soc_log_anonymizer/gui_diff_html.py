"""HTML diff report builders (no tkinter)."""

from __future__ import annotations

import difflib
import html
from datetime import datetime
from typing import Callable, Dict, Optional, Pattern

from .gui_logic import value_search_pattern
from .gui_theme import _TYPE_LEGEND_RU, TAG_COLORS_DARK, pseudonym_type

HTML_DIFF_CONTEXT_LINES = 3


def build_value_regex(values) -> Optional[Pattern[str]]:
    return value_search_pattern(values)


def render_html_line(
    line: str,
    pattern: Optional[Pattern[str]],
    type_of: Callable[[str], str],
) -> str:
    if pattern is None:
        return html.escape(line)
    parts = []
    pos = 0
    for match in pattern.finditer(line):
        if match.start() > pos:
            parts.append(html.escape(line[pos:match.start()]))
        matched = match.group(0)
        bg, fg = TAG_COLORS_DARK.get(type_of(matched), TAG_COLORS_DARK["VALUE"])
        parts.append(
            f'<span style="background:{bg};color:{fg};border-radius:3px;'
            f'padding:1px 4px;font-weight:600;">{html.escape(matched)}</span>'
        )
        pos = match.end()
    if pos < len(line):
        parts.append(html.escape(line[pos:]))
    return "".join(parts)


def build_diff_html(
    original: str,
    cleaned: str,
    mapping_table: Dict[str, str],
    reverse_mapping: Dict[str, str],
    org_name: str = "",
    context_lines: int = HTML_DIFF_CONTEXT_LINES,
) -> str:
    orig_pattern = build_value_regex(mapping_table.keys())
    pseudo_pattern = build_value_regex(reverse_mapping.keys())

    def orig_type(value: str) -> str:
        return pseudonym_type(mapping_table.get(value, ""))

    def pseudo_type(value: str) -> str:
        return pseudonym_type(value)

    lines_a = original.splitlines()
    lines_b = cleaned.splitlines()
    opcodes = difflib.SequenceMatcher(None, lines_a, lines_b, autojunk=False).get_opcodes()

    body_parts = []
    n_ops = len(opcodes)
    any_change = any(tag != "equal" for tag, *_ in opcodes)
    if not any_change:
        body_parts.append(
            '<div class="line line-ctx">Изменений нет — анонимизация ничего не заменила в этом тексте.</div>'
        )
    else:
        for idx, (tag, i1, i2, j1, j2) in enumerate(opcodes):
            if tag == "equal":
                block = lines_a[i1:i2]
                need_head = idx > 0
                need_tail = idx < n_ops - 1
                budget = (context_lines if need_head else 0) + (context_lines if need_tail else 0)
                if not (need_head or need_tail) or len(block) <= max(budget, 1):
                    shown = block
                    skipped = 0
                    head = tail = []
                else:
                    head = block[:context_lines] if need_head else []
                    tail = block[-context_lines:] if need_tail else []
                    skipped = len(block) - len(head) - len(tail)
                    shown = None
                if shown is not None:
                    for line in shown:
                        body_parts.append(f'<div class="line line-ctx">{html.escape(line)}</div>')
                else:
                    for line in head:
                        body_parts.append(f'<div class="line line-ctx">{html.escape(line)}</div>')
                    if skipped > 0:
                        body_parts.append(
                            f'<div class="line line-skip">⋯ ещё {skipped} неизменившихся строк(и) ⋯</div>'
                        )
                    for line in tail:
                        body_parts.append(f'<div class="line line-ctx">{html.escape(line)}</div>')
            else:
                for line in lines_a[i1:i2]:
                    rendered = render_html_line(line, orig_pattern, orig_type)
                    body_parts.append(
                        f'<div class="line line-old"><span class="marker">-</span> {rendered}</div>'
                    )
                for line in lines_b[j1:j2]:
                    rendered = render_html_line(line, pseudo_pattern, pseudo_type)
                    body_parts.append(
                        f'<div class="line line-new"><span class="marker">+</span> {rendered}</div>'
                    )

    types_present = sorted({pseudonym_type(p) for p in reverse_mapping})
    legend_rows = "".join(
        f'<tr><td><span class="swatch" style="background:{TAG_COLORS_DARK.get(t, TAG_COLORS_DARK["VALUE"])[0]};'
        f'color:{TAG_COLORS_DARK.get(t, TAG_COLORS_DARK["VALUE"])[1]}">{html.escape(t)}</span></td>'
        f'<td><b>{html.escape(_TYPE_LEGEND_RU.get(t, (t, ""))[0])}</b></td>'
        f'<td class="muted">{html.escape(_TYPE_LEGEND_RU.get(t, ("", ""))[1])}</td></tr>'
        for t in types_present
    ) or '<tr><td colspan="3" class="muted">Замен не было.</td></tr>'

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>SOC Log Anonymizer — diff-отчёт</title>
<style>
  body {{ background:#0a0f1e; color:#f1f5f9; font-family: Consolas, "Courier New", monospace;
          margin:0; padding:24px 32px 48px; line-height:1.55; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .subtitle {{ color:#94a3b8; font-size:13px; margin:0 0 20px; }}
  .banner {{ background:#141b2e; border:1px solid #263047; border-radius:8px; padding:14px 18px;
             margin-bottom:20px; font-size:13px; color:#cbd5e1; }}
  .diff-box {{ background:#111726; border:1px solid #263047; border-radius:8px; padding:14px 0;
               overflow-x:auto; }}
  .line {{ padding:2px 18px; white-space:pre-wrap; word-break:break-word; font-size:13px; }}
  .line-old {{ color:#fca5a5; }}
  .line-new {{ color:#86efac; }}
  .line-ctx {{ color:#64748b; }}
  .line-skip {{ color:#64748b; font-style:italic; text-align:center; padding:6px 18px; }}
  .marker {{ display:inline-block; width:14px; color:inherit; opacity:0.85; font-weight:700; }}
  .legend {{ margin-top:28px; }}
  .legend h2 {{ font-size:15px; margin:0 0 8px; }}
  .legend p {{ font-size:13px; color:#cbd5e1; max-width:900px; }}
  .legend table {{ border-collapse:collapse; margin-top:10px; font-size:12.5px; }}
  .legend td {{ padding:5px 12px 5px 0; vertical-align:top; }}
  .swatch {{ display:inline-block; padding:2px 8px; border-radius:4px; font-weight:700;
             font-size:11px; letter-spacing:0.03em; }}
  .muted {{ color:#94a3b8; }}
</style>
</head>
<body>
  <h1>🔀 SOC Log Anonymizer — diff-отчёт</h1>
  <p class="subtitle">Сформировано: {generated_at} · Организация: {html.escape(org_name)}</p>
  <div class="banner">
    ⚠️ Этот файл содержит исходные чувствительные данные наравне с
    анонимизированными (в "-"-строках) — обращайтесь с ним так же, как с
    исходным логом. Строки, начинающиеся с "-", — как было в исходном
    логе; строки с "+" — после анонимизации. Подсвечены (цветным фоном)
    ТОЛЬКО конкретные значения, которые были заменены.
  </div>
  <div class="diff-box">
    {"".join(body_parts)}
  </div>
  <div class="legend">
    <h2>Что означают цвета</h2>
    <p>
      Каждому типу данных назначен свой цвет фона — он одинаков и для
      исходного значения, и для псевдонима.
    </p>
    <table>
      {legend_rows}
    </table>
  </div>
</body>
</html>
"""
