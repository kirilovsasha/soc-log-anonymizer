"""Main window layout builders for AnonymizerGUI (tkinter)."""

from __future__ import annotations

import secrets
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from .gui_constants import (
    FONT_UI,
    ICON_COPY,
    ICON_DICE,
    ICON_DIFF,
    ICON_LOCK,
    ICON_MOON,
    ICON_OPEN,
    ICON_RUN,
    ICON_SAVE,
    ICON_SEARCH,
    ICON_STATS,
    ICON_TAB_CONFIG,
    ICON_TAB_LOG,
    ICON_TAB_MAP,
    ICON_UNDO,
    ICON_WARN,
)
if TYPE_CHECKING:
    from .gui import AnonymizerGUI


def build_main_ui(app: "AnonymizerGUI") -> None:
    """Construct the simplified main layout on app.root."""
    main = ttk.Frame(app.root, style="App.TFrame")
    main.pack(fill=tk.BOTH, expand=True)

    toolbar_outer, toolbar = app._card(main)
    toolbar_outer.pack(fill=tk.X, padx=8, pady=(8, 4))

    # Single compact header: workflow | session | overflow
    bar = ttk.Frame(toolbar, style="Card.TFrame")
    bar.pack(fill=tk.X, padx=10, pady=10)

    left = ttk.Frame(bar, style="Card.TFrame")
    left.pack(side=tk.LEFT)

    open_btn = ttk.Menubutton(
        left, text=f"{ICON_OPEN}  Открыть ▾", style="Ghost.TMenubutton"
    )
    open_menu = tk.Menu(open_btn, tearoff=False)
    open_menu.add_command(label="Файл…", command=app.open_file)
    open_menu.add_command(label="Папку…", command=app.open_folder)
    open_btn["menu"] = open_menu
    open_btn.pack(side=tk.LEFT, padx=(0, 6))
    # Same widget: processing disables both open entry points together.
    app.btn_open = open_btn
    app.btn_open_folder = open_btn

    app.btn_process = ttk.Button(
        left, text=f"{ICON_RUN}  Анонимизировать", style="Primary.TButton",
        command=app.start_processing_thread,
    )
    app.btn_process.pack(side=tk.LEFT, padx=(0, 6))

    app.btn_cancel = ttk.Button(
        left, text="Отменить", style="Danger.TButton",
        command=app.cancel_operation, state=tk.DISABLED,
    )
    app.btn_cancel.pack(side=tk.LEFT, padx=(0, 4))

    app.btn_undo = ttk.Button(
        left, text=f"{ICON_UNDO}", style="IconGhost.TButton", width=3,
        command=app.undo_last, state=tk.DISABLED,
    )
    app.btn_undo.pack(side=tk.LEFT)

    ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=14, pady=2)

    mid = ttk.Frame(bar, style="Card.TFrame")
    mid.pack(side=tk.LEFT, fill=tk.X, expand=True)

    ttk.Label(mid, text="Орг.", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 4))
    app.entry_org = ttk.Entry(mid, width=10, font=(FONT_UI, 9))
    app.entry_org.insert(0, app.config.org_name)
    app.entry_org.pack(side=tk.LEFT, padx=(0, 10))

    ttk.Label(mid, text="Соль", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 4))
    app.entry_salt = ttk.Entry(mid, width=18, font=(FONT_UI, 9))
    app.entry_salt.insert(0, secrets.token_hex(16))
    app.entry_salt.pack(side=tk.LEFT)
    vcmd = (app.root.register(app._validate_salt_live), "%P")
    app.entry_salt.configure(validate="key", validatecommand=vcmd)
    ttk.Button(
        mid, text=ICON_DICE, style="IconGhost.TButton", width=3,
        command=app.generate_new_salt,
    ).pack(side=tk.LEFT)

    right = ttk.Frame(bar, style="Card.TFrame")
    right.pack(side=tk.RIGHT)

    more = ttk.Menubutton(right, text="Ещё ▾", style="Ghost.TMenubutton")
    more_menu = tk.Menu(more, tearoff=False)
    more_menu.add_command(label=f"{ICON_COPY}  Копировать результат", command=app.copy_result)
    more_menu.add_command(label=f"{ICON_SAVE}  Сохранить результат", command=app.save_file)
    more_menu.add_command(label="Деанонимизировать", command=app.deanonymize_text)
    more_menu.add_command(label="Очистить всё", command=app.clear_all)
    more_menu.add_separator()
    format_menu = tk.Menu(more_menu, tearoff=False)
    for fmt in ("text", "json", "csv"):
        format_menu.add_radiobutton(
            label=fmt, value=fmt, variable=app.result_format,
        )
    more_menu.add_cascade(label="Формат результата", menu=format_menu)
    more_menu.add_separator()
    more_menu.add_command(label=f"{ICON_DIFF} HTML Diff отчёт", command=app.export_diff_html)
    more_menu.add_command(label=f"{ICON_STATS} Статистика", command=app.show_stats)
    more["menu"] = more_menu
    more.pack(side=tk.LEFT, padx=(0, 6))
    app.btn_deanonymize = more

    ttk.Button(
        right, text=ICON_MOON, style="IconGhost.TButton", width=3,
        command=app._toggle_dark_mode,
    ).pack(side=tk.LEFT)

    # --- Status ---
    status_bar = ttk.Frame(main, style="StatusBar.TFrame")
    status_bar.pack(fill=tk.X, padx=12, pady=(0, 8))
    ttk.Label(status_bar, text="СОСТОЯНИЕ", style="StatusBar.TLabel").pack(
        side=tk.LEFT, padx=(12, 8), pady=8
    )
    app.status_label = ttk.Label(status_bar, text="Готов к работе", style="StatusIdle.TLabel")
    app.status_label.pack(side=tk.LEFT, pady=4)
    app.progress = ttk.Progressbar(
        status_bar, orient=tk.HORIZONTAL, length=180, mode="determinate", style="TProgressbar"
    )
    app.progress.pack(side=tk.RIGHT, padx=(10, 12), pady=8)
    app.progress_label = ttk.Label(status_bar, text="0%", style="StatusBar.TLabel")
    app.progress_label.pack(side=tk.RIGHT, padx=(0, 4))
    ttk.Label(status_bar, text="Прогресс", style="StatusBar.TLabel").pack(
        side=tk.RIGHT, padx=(0, 4)
    )

    # --- Notebook ---
    app.notebook = ttk.Notebook(main)
    app.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

    tab_logs = ttk.Frame(app.notebook, style="App.TFrame")
    app.notebook.add(tab_logs, text=f"{ICON_TAB_LOG}  Редактор логов")
    _build_logs_tab(app, tab_logs)

    tab_mapping = ttk.Frame(app.notebook, style="App.TFrame")
    app.notebook.add(tab_mapping, text=f"{ICON_TAB_MAP}  Таблица соответствия")
    _build_mapping_tab(app, tab_mapping)

    tab_config = ttk.Frame(app.notebook, style="App.TFrame")
    app.notebook.add(tab_config, text=f"{ICON_TAB_CONFIG}  Конфигурация")
    _build_config_tab(app, tab_config)


def _build_logs_tab(app: "AnonymizerGUI", tab_logs: ttk.Frame) -> None:
    files_outer, files_card = app._card(tab_logs)
    files_outer.pack(fill=tk.X, padx=4, pady=(4, 0))
    files_header = ttk.Frame(files_card, style="Card.TFrame")
    files_header.pack(fill=tk.X, padx=12, pady=(8, 3))
    ttk.Label(files_header, text="ФАЙЛЫ", style="Section.TLabel").pack(side=tk.LEFT)
    app.files_count_label = ttk.Label(files_header, text="0 файлов", style="Muted.TLabel")
    app.files_count_label.pack(side=tk.LEFT, padx=(12, 0))

    files_bar = ttk.Frame(files_card, style="Card.TFrame")
    files_bar.pack(fill=tk.X, padx=12, pady=(0, 9))
    app.files_list = tk.Listbox(
        files_bar, height=2, exportselection=False, relief=tk.FLAT, borderwidth=0, activestyle="none"
    )
    app.files_list.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
    files_scroll = ttk.Scrollbar(files_bar, orient=tk.VERTICAL, command=app.files_list.yview)
    app.files_list.configure(yscrollcommand=files_scroll.set)
    files_scroll.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
    ttk.Button(files_bar, text="Удалить", style="Ghost.TButton", command=app.remove_loaded_file).pack(
        side=tk.LEFT
    )
    ttk.Button(
        files_bar, text="↑", width=3, style="IconGhost.TButton",
        command=lambda: app.move_loaded_file(-1),
    ).pack(side=tk.LEFT, padx=2)
    ttk.Button(
        files_bar, text="↓", width=3, style="IconGhost.TButton",
        command=lambda: app.move_loaded_file(1),
    ).pack(side=tk.LEFT)

    log_search = ttk.Frame(tab_logs, style="App.TFrame")
    log_search.pack(fill=tk.X, padx=4, pady=(4, 0))
    ttk.Label(log_search, text=f"{ICON_SEARCH} Поиск", style="Muted.TLabel").pack(
        side=tk.LEFT, padx=(4, 6)
    )
    app.log_search_entry = ttk.Entry(log_search, width=32)
    app.log_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    app.log_search_entry.bind("<Return>", lambda e: app._find_in_logs(1))
    app.log_search_target = ttk.Combobox(
        log_search, values=("Input", "Output"), state="readonly", width=9
    )
    app.log_search_target.set("Input")
    app.log_search_target.pack(side=tk.LEFT, padx=6)
    ttk.Button(log_search, text="Найти", style="Ghost.TButton",
               command=lambda: app._find_in_logs(1)).pack(side=tk.LEFT, padx=2)
    ttk.Button(log_search, text="Назад", style="Ghost.TButton",
               command=lambda: app._find_in_logs(-1)).pack(side=tk.LEFT, padx=2)
    ttk.Button(log_search, text="◀ Diff", style="Ghost.TButton",
               command=lambda: app._navigate_diff(-1)).pack(side=tk.LEFT, padx=2)
    ttk.Button(log_search, text="Diff ▶", style="Ghost.TButton",
               command=lambda: app._navigate_diff(1)).pack(side=tk.LEFT, padx=2)

    paned = ttk.PanedWindow(tab_logs, orient=tk.HORIZONTAL)
    app.editor_paned = paned
    paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    left_outer, left_card = app._card(paned)
    ttk.Label(left_card, text="Исходные логи / Ответ LLM (Input)", style="Heading.TLabel").pack(
        anchor="w", padx=12, pady=(10, 4)
    )
    app.txt_input, app.v_scroll_left, _ = app._create_scrolled_text(
        left_card,
        lambda first, last: app._sync_yscroll(app.v_scroll_left, (app.txt_output,), first, last),
    )
    app.txt_input.bind("<Motion>", app._on_input_motion)
    app.txt_input.bind("<Leave>", lambda e: app._hide_tooltip())
    app.txt_input.bind("<<Modified>>", app._on_input_modified)
    paned.add(left_outer, weight=1)

    right_outer, right_card = app._card(paned)
    ttk.Label(right_card, text="Результат (Output)", style="Heading.TLabel").pack(
        anchor="w", padx=12, pady=(10, 4)
    )
    app.txt_output, app.v_scroll_right, _ = app._create_scrolled_text(
        right_card,
        lambda first, last: app._sync_yscroll(app.v_scroll_right, (app.txt_input,), first, last),
    )
    paned.add(right_outer, weight=1)

    app.legend_frame = ttk.Frame(tab_logs, style="App.TFrame")
    app.legend_frame.pack(fill=tk.X, padx=12, pady=(0, 4))
    app._legend_counts = {}


def _build_mapping_tab(app: "AnonymizerGUI", tab_mapping: ttk.Frame) -> None:
    from .gui_constants import ICON_EXPORT

    search_outer, search_card = app._card(tab_mapping)
    search_outer.pack(fill=tk.X, padx=8, pady=(8, 6))
    search_row = ttk.Frame(search_card, style="Card.TFrame")
    search_row.pack(fill=tk.X, padx=12, pady=10)

    ttk.Label(search_row, text=f"{ICON_SEARCH}  Поиск", style="Muted.TLabel").pack(
        side=tk.LEFT, padx=(0, 6)
    )
    app.entry_search = ttk.Entry(search_row, width=28, font=(FONT_UI, 9))
    app.entry_search.pack(side=tk.LEFT)
    app.entry_search.bind("<KeyRelease>", app.filter_mapping_table)
    app.mapping_type_filter = ttk.Combobox(
        search_row, values=("Все типы",), state="readonly", width=12
    )
    app.mapping_type_filter.set("Все типы")
    app.mapping_type_filter.pack(side=tk.LEFT, padx=8)
    app.mapping_type_filter.bind("<<ComboboxSelected>>", app.filter_mapping_table)

    ttk.Button(
        search_row, text=f"{ICON_LOCK}  Экспорт JSON", style="Ghost.TButton",
        command=app.export_mapping_json,
    ).pack(side=tk.RIGHT, padx=(6, 0))
    ttk.Button(
        search_row, text=f"{ICON_EXPORT}  Экспорт CSV", style="Ghost.TButton",
        command=app.export_mapping_csv,
    ).pack(side=tk.RIGHT)

    ttk.Label(
        tab_mapping,
        text=f"{ICON_WARN}  Таблица содержит исходные чувствительные данные.",
        style="Banner.TLabel",
        anchor="w",
    ).pack(fill=tk.X, padx=8, pady=(0, 6))

    table_outer, table_card = app._card(tab_mapping)
    table_outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
    table_inner = ttk.Frame(table_card, style="Card.TFrame")
    table_inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

    app.map_tree = ttk.Treeview(
        table_inner, columns=("Original", "Pseudonym"), show="headings", selectmode="browse"
    )
    app.map_tree.heading("Original", text="Оригинальное значение")
    app.map_tree.heading("Pseudonym", text="Псевдоним")
    app.map_tree.column("Original", width=450)
    app.map_tree.column("Pseudonym", width=450)
    map_scroll = ttk.Scrollbar(table_inner, orient=tk.VERTICAL, command=app.map_tree.yview)
    app.map_tree.configure(yscroll=map_scroll.set)
    app.map_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    map_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    app.map_tree.bind("<Motion>", app._on_tree_motion)
    app.map_tree.bind("<Leave>", lambda e: app._hide_tooltip())
    app.map_tree.bind("<Double-1>", app._jump_from_mapping)


def _build_config_tab(app: "AnonymizerGUI", tab_config: ttk.Frame) -> None:
    config_banner_outer, config_banner_card = app._card(tab_config)
    config_banner_outer.pack(fill=tk.X, padx=8, pady=(8, 6))
    app.lbl_config_path = ttk.Label(
        config_banner_card, text="", style="Banner.TLabel", anchor="w",
        wraplength=1100, justify=tk.LEFT,
    )
    app.lbl_config_path.pack(fill=tk.X, padx=12, pady=8)

    config_actions = ttk.Frame(tab_config, style="App.TFrame")
    config_actions.pack(fill=tk.X, padx=8, pady=(0, 6))
    ttk.Button(config_actions, text="Открыть…", style="Ghost.TButton",
               command=app.load_config_file).pack(side=tk.LEFT, padx=(0, 6))
    ttk.Button(config_actions, text="Сохранить", style="Primary.TButton",
               command=app.save_config_editor).pack(side=tk.LEFT, padx=6)
    ttk.Button(config_actions, text="Сохранить как…", style="Ghost.TButton",
               command=app.save_config_editor_as).pack(side=tk.LEFT, padx=6)
    ttk.Button(config_actions, text="Перезагрузить", style="Ghost.TButton",
               command=app.reload_config_editor).pack(side=tk.LEFT, padx=6)
    ttk.Button(config_actions, text="Проверить", style="Ghost.TButton",
               command=app.validate_config_editor).pack(side=tk.LEFT, padx=6)
    ttk.Button(config_actions, text="Сбросить", style="Danger.TButton",
               command=app.reset_config_editor).pack(side=tk.LEFT, padx=6)

    # Allowlist editor (human-friendly)
    allow_outer, allow_card = app._card(tab_config)
    allow_outer.pack(fill=tk.X, padx=8, pady=(0, 6))
    allow_header = ttk.Frame(allow_card, style="Card.TFrame")
    allow_header.pack(fill=tk.X, padx=12, pady=(10, 4))
    ttk.Label(allow_header, text="Allowlist — не маскировать", style="Section.TLabel").pack(
        side=tk.LEFT
    )
    ttk.Label(
        allow_header,
        text="Точные значения (IP, логины…). Сохраняются в конфиг.",
        style="Muted.TLabel",
    ).pack(side=tk.LEFT, padx=12)

    allow_body = ttk.Frame(allow_card, style="Card.TFrame")
    allow_body.pack(fill=tk.X, padx=12, pady=(0, 10))

    app.allowlist_list = tk.Listbox(
        allow_body, height=5, exportselection=False, relief=tk.FLAT, borderwidth=0
    )
    app.allowlist_list.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
    allow_scroll = ttk.Scrollbar(allow_body, orient=tk.VERTICAL, command=app.allowlist_list.yview)
    app.allowlist_list.configure(yscrollcommand=allow_scroll.set)
    allow_scroll.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))

    allow_side = ttk.Frame(allow_body, style="Card.TFrame")
    allow_side.pack(side=tk.LEFT, fill=tk.Y)
    app.allowlist_entry = ttk.Entry(allow_side, width=22, font=(FONT_UI, 9))
    app.allowlist_entry.pack(fill=tk.X, pady=(0, 4))
    app.allowlist_entry.bind("<Return>", lambda e: app.add_allowlist_value())
    ttk.Button(allow_side, text="Добавить", style="Ghost.TButton",
               command=app.add_allowlist_value).pack(fill=tk.X, pady=2)
    ttk.Button(allow_side, text="Удалить", style="Ghost.TButton",
               command=app.remove_allowlist_value).pack(fill=tk.X, pady=2)
    ttk.Button(allow_side, text="+ DNS", style="Ghost.TButton",
               command=lambda: app.add_allowlist_preset("dns_public")).pack(fill=tk.X, pady=2)
    ttk.Button(allow_side, text="+ Windows", style="Ghost.TButton",
               command=lambda: app.add_allowlist_preset("windows_builtin")).pack(fill=tk.X, pady=2)

    # Advanced JSON
    ttk.Label(
        tab_config, text="Расширенный JSON", style="Muted.TLabel"
    ).pack(anchor="w", padx=12, pady=(0, 2))
    config_outer, config_card = app._card(tab_config)
    config_outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
    app.txt_config, app.v_scroll_config, _ = app._create_scrolled_text(
        config_card, lambda first, last: app.v_scroll_config.set(first, last)
    )
    app._refresh_config_editor()
