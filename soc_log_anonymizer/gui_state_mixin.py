"""Mixin providing GuiStateMixin methods for AnonymizerGUI."""
from __future__ import annotations

import base64
import glob
import json
import logging
import os
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import messagebox

from .anonymizer import SOCLogAnonymizer
from .gui_constants import (
    AUTOSAVE_INTERVAL_MS,
    DEFAULT_FONT_SIZE,
    MAX_FONT_SIZE,
    MIN_FONT_SIZE,
)
from .io_utils import restrict_sensitive_file
from .paths import (
    draft_path_for_pid,
    drafts_dir,
    ensure_dir,
    gui_state_path,
    set_portable_mode,
    user_data_dir,
)

logger = logging.getLogger("soc_log_anonymizer")


class GuiStateMixin:
    def _load_gui_state(self) -> dict:
        """Load window-only state; this is not an import/export setting."""
        try:
            with open(self._gui_state_path, "r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}


    def _restore_gui_state(self) -> None:
        geometry = self._gui_state.get("geometry")
        if isinstance(geometry, str) and geometry:
            try:
                self.root.geometry(geometry)
            except tk.TclError:
                logger.debug("Saved GUI geometry is invalid: %r", geometry)
        if self._gui_state.get("zoomed") and sys.platform == "win32":
            try:
                self.root.state("zoomed")
            except tk.TclError:
                pass
        self.dark_mode.set(bool(self._gui_state.get("dark_mode", False)))
        try:
            self.font_size.set(max(MIN_FONT_SIZE, min(MAX_FONT_SIZE,
                                                       int(self._gui_state.get("font_size", DEFAULT_FONT_SIZE)))))
        except (TypeError, ValueError):
            self.font_size.set(DEFAULT_FONT_SIZE)
        self.autosave_drafts.set(bool(self._gui_state.get("autosave_drafts", True)))
        self.auto_sidecar_large.set(bool(self._gui_state.get("auto_sidecar_large", True)))
        self._configure_styles()
        self._apply_font_size()
        self.root.after_idle(self._restore_editor_sash)


    def _restore_editor_sash(self) -> None:
        sash = self._gui_state.get("editor_sash")
        if sash is None or not hasattr(self, "editor_paned"):
            return
        try:
            self.editor_paned.sashpos(0, int(sash))
        except (tk.TclError, TypeError, ValueError):
            logger.debug("Saved editor sash is invalid: %r", sash)


    def _save_gui_state(self) -> None:
        state = {
            "geometry": self.root.geometry(),
            "zoomed": sys.platform == "win32" and self.root.state() == "zoomed",
            "dark_mode": bool(self.dark_mode.get()),
            "font_size": int(self.font_size.get()),
            "autosave_drafts": bool(self.autosave_drafts.get()),
            "auto_sidecar_large": bool(self.auto_sidecar_large.get()),
            "portable_mode": bool(self.portable_mode_var.get()),
        }
        try:
            state["editor_sash"] = int(self.editor_paned.sashpos(0))
        except (AttributeError, tk.TclError):
            pass
        try:
            ensure_dir(os.path.dirname(self._gui_state_path) or ".")
            with open(self._gui_state_path, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, indent=2)
        except OSError as exc:
            logger.debug("Could not save GUI state: %s", exc)


    def _set_window_icon(self):
        """Генерирует простую иконку (закрашенный круг фирменного цвета)
        в формате PPM и передаёт её как tk.PhotoImage. Без сторонних
        библиотек и файлов изображений — PPM поддерживается tkinter "из
        коробки", нужно только собрать байты и закодировать в base64."""
        try:
            size = 32
            cx = cy = size / 2
            r = size / 2 - 2
            accent = bytes((0x4F, 0x46, 0xE5))  # PALETTE_LIGHT["accent"]
            bg = bytes((0xFF, 0xFF, 0xFF))
            pixels = bytearray()
            for y in range(size):
                for x in range(size):
                    dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
                    pixels += accent if dist <= r else bg
            ppm = f"P6\n{size} {size}\n255\n".encode("ascii") + bytes(pixels)
            self._icon_photo = tk.PhotoImage(data=base64.b64encode(ppm).decode("ascii"))
            self.root.iconphoto(True, self._icon_photo)
        except tk.TclError as e:
            logger.debug("Не удалось установить иконку окна: %s", e)


    def _schedule_autosave(self):
        self.root.after(AUTOSAVE_INTERVAL_MS, self._autosave_tick)


    def _autosave_tick(self):
        try:
            if (
                self.autosave_drafts.get()
                and not getattr(self.txt_input, "_is_placeholder", False)
            ):
                content = self.txt_input.get("1.0", tk.END)
                if content.strip():
                    self._write_draft_file(self._autosave_path, content)
        except OSError as e:
            logger.debug("Автосохранение черновика не удалось: %s", e)
        self._schedule_autosave()


    @staticmethod
    def _write_draft_file(path: str, content: str) -> None:
        """Пишет черновик лога (потенциально НЕанонимизированные, т.е.
        чувствительные данные) с правами только для владельца
        (POSIX 0600 / Windows ACL)."""
        ensure_dir(os.path.dirname(path) or ".")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        warning = restrict_sensitive_file(path)
        if warning:
            logger.debug("%s", warning)


    def _offer_draft_recovery(self):
        """При старте ищет файлы черновиков от предыдущих (аварийно
        завершённых) сессий и предлагает восстановить самый свежий."""
        if not self.autosave_drafts.get():
            return
        pattern = os.path.join(drafts_dir(self._portable), "soc_log_anonymizer_draft_*.txt")
        candidates = [p for p in glob.glob(pattern) if p != self._autosave_path]
        # Legacy drafts in %TEMP% from older versions.
        legacy = os.path.join(tempfile.gettempdir(), "soc_log_anonymizer_draft_*.txt")
        candidates.extend(p for p in glob.glob(legacy) if p != self._autosave_path)
        if not candidates:
            return
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        latest = candidates[0]
        try:
            proceed = messagebox.askyesno(
                "Восстановление черновика",
                f"Найден несохранённый черновик от предыдущей сессии "
                f"({os.path.basename(latest)}). Восстановить его в поле ввода?"
            )
            if proceed:
                with open(latest, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                self._set_widget_content(self.txt_input, content)
        finally:
            for p in candidates:
                try:
                    os.remove(p)
                except OSError:
                    pass


    def _cleanup_autosave_file(self):
        try:
            if os.path.exists(self._autosave_path):
                os.remove(self._autosave_path)
        except OSError:
            pass


    def _on_autosave_toggle(self):
        if not self.autosave_drafts.get():
            self._cleanup_autosave_file()
            self._set_status("Автосохранение черновика выключено", "Muted")
        else:
            self._set_status("Автосохранение черновика включено", "Info")
        self._save_gui_state()


    def _reset_session_timer(self):
        if self._session_timer:
            self._session_timer.cancel()
        minutes = self.config.session_timeout_minutes
        if minutes and minutes > 0:
            self._session_timer = threading.Timer(minutes * 60, self._on_session_timeout)
            self._session_timer.daemon = True
            self._session_timer.start()


    def _on_session_timeout(self):
        self.root.after(0, self._session_timeout_ui)


    def _session_timeout_ui(self):
        if self.anonymizer and self.anonymizer.mapping_table:
            self.anonymizer.clear_sensitive_data()
            self.anonymizer = SOCLogAnonymizer(config=self.config)
            self.refresh_mapping_table()
            self._set_status("Сессия истекла — таблица соответствия очищена", "Warning")
            logger.info("Сессия истекла по таймауту — mapping-таблица очищена")
        self._reset_session_timer()


    def _on_close(self):
        if self._session_timer:
            self._session_timer.cancel()
        self._save_gui_state()
        if self.anonymizer:
            self.anonymizer.clear_sensitive_data()
        self._cleanup_autosave_file()
        self.root.destroy()


    def _on_portable_toggle(self):
        enabled = bool(self.portable_mode_var.get())
        try:
            set_portable_mode(enabled)
        except OSError as exc:
            messagebox.showerror(
                "Portable-режим",
                f"Не удалось изменить portable.flag рядом с приложением:\n{exc}\n\n"
                "Положите exe в каталог с правом записи или задайте "
                "SOC_ANON_PORTABLE=1.",
            )
            self.portable_mode_var.set(self._portable)
            return
        self._portable = enabled
        self._gui_state_path = gui_state_path(enabled)
        self._autosave_path = draft_path_for_pid(portable=enabled)
        self._save_gui_state()
        messagebox.showinfo(
            "Portable-режим",
            "Portable-режим " + ("включён" if enabled else "выключен") + ".\n"
            "Часть путей применится полностью после перезапуска приложения.\n\n"
            f"Данные: {user_data_dir(enabled)}",
        )


    def _on_window_resize(self, event):
        """Adapt the status meter to the available width."""
        if event.widget is not self.root:
            return
        if hasattr(self, "progress"):
            self.progress.configure(length=max(120, min(260, event.width // 5)))
