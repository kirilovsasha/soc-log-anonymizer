"""Mixin providing GuiProcessMixin methods for AnonymizerGUI."""
from __future__ import annotations

import logging
import os
import secrets
import threading
import tkinter as tk
from tkinter import messagebox
from typing import List

from .anonymizer import SOCLogAnonymizer
from .audit import log_audit_event
from .gui_constants import GUI_DISPLAY_CHAR_LIMIT, GUI_SIDECAR_AUTO_MB
from .gui_logic import (
    compute_progress_pct,
    format_result_status,
    format_size_warning,
    salt_entropy_warning,
    truncate_display_text,
)
from .io_utils import restrict_sensitive_file
from .paths import ensure_dir, user_data_dir

logger = logging.getLogger("soc_log_anonymizer")


class GuiProcessMixin:
    def start_processing_thread(self):
        raw_text = self._text_value(self.txt_input)
        if not raw_text:
            messagebox.showwarning("Предупреждение", "Введите или загрузите текст логов!")
            return

        # Проверка размера при "Открыть файл" покрывает только этот путь —
        # текст, вставленный напрямую (Ctrl+V) или набранный в Input, её
        # не проходит. Мегабайты текста в tk.Text и так не самый быстрый
        # виджет, а дальнейшая подсветка заменённых значений (см.
        # _refresh_diff_highlighting) добавляет накладных расходов сверху
        # — предупреждаем и даём выбор, а не подвешиваем интерфейс молча.
        size_mb = len(raw_text.encode("utf-8")) / (1024 * 1024)
        if size_mb > self.config.max_input_size_mb or (
            self.auto_sidecar_large.get() and size_mb >= GUI_SIDECAR_AUTO_MB
        ):
            if not self._prefer_sidecar:
                choice = messagebox.askyesnocancel(
                    "Большой объём текста",
                    format_size_warning(size_mb, self.config.max_input_size_mb)
                    + "\n\nДа — обработать и сохранить полный результат в sidecar (*.anon.log), "
                    "в окне показать превью\n"
                    "Нет — обработать с полной отрисовкой в GUI\n"
                    "Отмена — прервать\n\n"
                    "Для пайплайнов удобнее CLI: soc-log-anonymizer-cli.exe",
                )
                if choice is None:
                    return
                self._prefer_sidecar = bool(choice)

        org_name = (self.config.org_name or "").strip() or "bank"
        salt = self._entry_value(self.entry_salt) or secrets.token_hex(16)

        warning = salt_entropy_warning(salt)
        if warning:
            proceed = messagebox.askyesno("Слабая соль", f"{warning}\n\nПродолжить с этой солью?")
            if not proceed:
                return

        self.btn_process.config(state=tk.DISABLED)
        self._set_cancel_visible(True)
        self._cancel_event.clear()
        self._set_progress(0)
        self._set_status("Обработка…", "Info")

        new_anonymizer = SOCLogAnonymizer(salt=salt, org_name=org_name, config=self.config)

        threading.Thread(
            target=self._async_process,
            args=(raw_text, new_anonymizer),
            daemon=True
        ).start()


    def _async_process(self, raw_text: str, new_anonymizer: SOCLogAnonymizer):
        stripped = raw_text.strip()
        is_single_json = (stripped.startswith("{") and stripped.endswith("}")) or \
                          (stripped.startswith("[") and stripped.endswith("]"))

        if is_single_json:
            # Единый JSON-документ нельзя обрабатывать построчно —
            # прогресс покажет только начало и конец.
            self.root.after(0, self._set_progress, 10)
            cleaned_text = new_anonymizer.anonymize(raw_text)
            if self._cancel_event.is_set():
                self.root.after(0, self._processing_cancelled, new_anonymizer)
                return
            self.root.after(0, self._set_progress, 100)
        else:
            lines = raw_text.splitlines(keepends=True)
            total = max(len(lines), 1)
            out_parts = []
            for i, out_line in enumerate(new_anonymizer.anonymize_stream(lines), 1):
                out_parts.append(out_line)
                if self._cancel_event.is_set():
                    self.root.after(0, self._processing_cancelled, new_anonymizer,
                                    "".join(out_parts), i, total)
                    return
                if i % 25 == 0 or i == total:
                    self.root.after(0, self._set_progress, compute_progress_pct(i, total))
            cleaned_text = "".join(out_parts)

        is_safe, issues = new_anonymizer.verify(cleaned_text)
        self.root.after(0, self._update_ui_after_processing, new_anonymizer, cleaned_text, is_safe, issues)


    def _processing_cancelled(self, anonymizer, partial_text: str = "", processed: int = 0,
                              total: int = 0):
        if partial_text:
            safe, issues = anonymizer.verify(partial_text)
            self.txt_output.delete("1.0", tk.END)
            self.txt_output.insert(tk.END, partial_text)
            self.anonymizer = anonymizer
            self.refresh_mapping_table()
            self._refresh_diff_highlighting()
            self._last_file_report = [{
                "status": "cancelled_partial",
                "processed_lines": processed,
                "total_lines": total,
                "safe": safe,
                "issues": issues,
            }]
            self._set_progress(compute_progress_pct(processed, total))
            self._set_status(
                f"Отменено: сохранён частичный результат ({processed}/{total} строк)",
                "Warning",
            )
        anonymizer.clear_sensitive_data()
        self.btn_process.config(state=tk.NORMAL)
        self._set_cancel_visible(False)
        if not partial_text:
            self._set_status("Обработка отменена", "Muted")


    def _update_ui_after_processing(self, new_anonymizer: SOCLogAnonymizer, cleaned_text: str,
                                     is_safe: bool, issues: List[str]):
        # Сохраняем предыдущее состояние для отмены (undo)
        prev_output = self.txt_output.get("1.0", tk.END)
        self._undo_stack.append((self.anonymizer, prev_output))
        self.btn_undo.config(state=tk.NORMAL)

        # Единственное место, где self.anonymizer переприсваивается —
        # выполняется в главном потоке.
        self.anonymizer = new_anonymizer
        self.config = new_anonymizer.config
        self._reset_session_timer()

        self.txt_output.delete("1.0", tk.END)
        force_sidecar = self._prefer_sidecar or len(cleaned_text) > GUI_DISPLAY_CHAR_LIMIT
        display, truncated = truncate_display_text(cleaned_text, GUI_DISPLAY_CHAR_LIMIT)
        self._full_output_text = cleaned_text if truncated or force_sidecar else None
        self.txt_output.insert(tk.END, display)
        if force_sidecar or truncated:
            if self._loaded_files:
                out_path = self._loaded_files[0] + ".anon.log"
            else:
                out_path = os.path.join(
                    ensure_dir(user_data_dir(self._portable)),
                    f"anonymized_{os.getpid()}.anon.log",
                )
            try:
                with open(out_path, "w", encoding="utf-8") as handle:
                    handle.write(cleaned_text)
                warning = restrict_sensitive_file(out_path)
                if warning:
                    logger.warning("%s", warning)
                self._set_status(
                    f"Полный результат: {out_path}; в окне — превью",
                    "Warning",
                )
            except OSError as exc:
                logger.warning("Could not write preview sidecar: %s", exc)
        self.refresh_mapping_table()
        self._refresh_diff_highlighting()
        self.btn_process.config(state=tk.NORMAL)
        self._set_cancel_visible(False)
        self._set_progress(100)

        status_text, status_kind = format_result_status(is_safe, issues)
        self._set_status(status_text, status_kind)
        if is_safe:
            logger.info("Анонимизация завершена: безопасно, %d значений в mapping",
                        len(new_anonymizer.mapping_table))
        else:
            for issue in issues:
                logger.warning("Gatekeeper: %s", issue)

        log_audit_event(new_anonymizer.config.audit_log_path, {
            "action": "anonymize",
            "source": "gui",
            "org_name": new_anonymizer.config.org_name,
            "stats_by_type": new_anonymizer.get_stats(),
            "unique_values_replaced": len(new_anonymizer.mapping_table),
            "gatekeeper_safe": is_safe,
            "gatekeeper_issue_count": len(issues),
        }, max_bytes=new_anonymizer.config.audit_log_max_bytes, backup_count=new_anonymizer.config.audit_log_backup_count)
        self._last_file_report = [{
            "file": os.path.basename(self._loaded_files[0]) if len(self._loaded_files) == 1 else "combined input",
            "status": "ok" if is_safe else "unsafe",
            "structural_status": "structured" if new_anonymizer.get_stats() else "fallback",
            "replacements": sum(new_anonymizer.get_stats().values()),
            "safe": is_safe,
            "issues": issues,
        }]


    def undo_last(self):
        if not self._undo_stack:
            return
        prev_anonymizer, prev_output = self._undo_stack.pop()
        self.anonymizer = prev_anonymizer
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, prev_output.rstrip("\n"))
        self.refresh_mapping_table()
        self._refresh_diff_highlighting()
        self._set_status("Отменено", "Muted")
        if not self._undo_stack:
            self.btn_undo.config(state=tk.DISABLED)


    def deanonymize_text(self):
        input_text = self._text_value(self.txt_input)
        if not input_text:
            messagebox.showwarning("Предупреждение", "Введите текст для де-анонимизации в левое окно!")
            return
        if not self.anonymizer or not self.anonymizer.reverse_mapping:
            messagebox.showwarning("Предупреждение", "Таблица замен пуста! Сначала выполните анонимизацию.")
            return

        restored_text = self.anonymizer.deanonymize(input_text)
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, restored_text)
        # Раньше вызывалось ДО insert — diff считался по ещё пустому
        # Output, и подсветка/навигация после де-анонимизации всегда были
        # пустыми.
        self._refresh_diff_highlighting()
        self._reset_session_timer()
        self._set_status("Де-анонимизировано", "Purple")
        log_audit_event(self.anonymizer.config.audit_log_path, {
            "action": "deanonymize",
            "source": "gui",
            "unique_values_available": len(self.anonymizer.reverse_mapping),
        }, max_bytes=self.anonymizer.config.audit_log_max_bytes, backup_count=self.anonymizer.config.audit_log_backup_count)


    def _set_progress(self, pct: int):
        self.progress["value"] = pct
        if hasattr(self, "progress_label"):
            self.progress_label.configure(text=f"{int(pct)}%")


    def _update_file_summary(self):
        """Keep the file panel summary in sync without changing file order."""
        if hasattr(self, "files_count_label"):
            count = len(self._loaded_files)
            self.files_count_label.configure(
                text=f"{count} файл" if count == 1 else f"{count} файлов"
            )
