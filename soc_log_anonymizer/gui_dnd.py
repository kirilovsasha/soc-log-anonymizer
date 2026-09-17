"""Drag-and-drop файлов из Проводника в GUI на Windows (WM_DROPFILES).

Без tkdnd и без сторонних пакетов: ctypes + штатный shell32.
На не-Windows enable_windows_file_drop() сразу возвращает False.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from ctypes import wintypes
from typing import Callable, List, Tuple

logger = logging.getLogger("soc_log_anonymizer")

WM_DROPFILES = 0x0233
WM_COPYDATA = 0x004A
WM_COPYGLOBALDATA = 0x0049
MSGFLT_ALLOW = 1
GWLP_WNDPROC = -4
GA_ROOT = 2
DRAG_QUERY_FILE_COUNT = 0xFFFFFFFF

DropCallback = Callable[[Tuple[str, ...]], None]


def list_hdrop_paths(drag_query_file, hdrop) -> List[str]:
    """Собирает пути из HDROP (DragQueryFileW)."""
    count = int(drag_query_file(hdrop, DRAG_QUERY_FILE_COUNT, None, 0) or 0)
    paths: List[str] = []
    for index in range(count):
        length = int(drag_query_file(hdrop, index, None, 0) or 0)
        if length <= 0:
            continue
        buf = ctypes.create_unicode_buffer(length + 1)
        drag_query_file(hdrop, index, buf, length + 1)
        if buf.value:
            paths.append(buf.value)
    return paths


def _allow_drop_messages(user32, hwnd: int) -> None:
    """UIPI: разрешить WM_DROPFILES от не-elevated Explorer к окну GUI."""
    changer = getattr(user32, "ChangeWindowMessageFilterEx", None)
    if changer is None:
        return
    changer.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.DWORD, ctypes.c_void_p]
    changer.restype = wintypes.BOOL
    for msg in (WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA):
        try:
            changer(hwnd, msg, MSGFLT_ALLOW, None)
        except OSError:
            continue


def _drop_target_hwnd(user32, widget_hwnd: int) -> int:
    ancestor = user32.GetAncestor(widget_hwnd, GA_ROOT)
    return int(ancestor or widget_hwnd)


def enable_windows_file_drop(widget, callback: DropCallback) -> bool:
    """Включает приём файлов из Проводника на toplevel Tk-окне.

    ``callback`` вызывается через ``widget.after(0, ...)`` со списком путей.
    Ссылки на WNDPROC сохраняются на виджете, иначе GC сломает окно.
    При Destroy прежняя оконная процедура восстанавливается.
    """
    if sys.platform != "win32" or widget is None or callback is None:
        return False
    try:
        widget_hwnd = int(widget.winfo_id())
    except (AttributeError, ValueError, TypeError, OSError):
        return False
    if widget_hwnd == 0:
        return False

    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32
    is_64 = ctypes.sizeof(ctypes.c_void_p) == 8
    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(
        LRESULT, wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM,
    )

    if is_64:
        get_long = user32.GetWindowLongPtrW
        set_long = user32.SetWindowLongPtrW
    else:
        get_long = user32.GetWindowLongW
        set_long = user32.SetWindowLongW
    get_long.restype = ctypes.c_void_p
    get_long.argtypes = [wintypes.HWND, ctypes.c_int]
    set_long.restype = ctypes.c_void_p
    set_long.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]

    user32.GetAncestor.restype = wintypes.HWND
    user32.GetAncestor.argtypes = [wintypes.HWND, ctypes.c_uint]
    user32.CallWindowProcW.restype = LRESULT
    user32.CallWindowProcW.argtypes = [
        ctypes.c_void_p, wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM,
    ]
    shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
    shell32.DragQueryFileW.restype = wintypes.UINT
    shell32.DragQueryFileW.argtypes = [
        wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT,
    ]
    shell32.DragFinish.argtypes = [wintypes.HANDLE]

    hwnd = _drop_target_hwnd(user32, widget_hwnd)
    try:
        shell32.DragAcceptFiles(hwnd, True)
        if hwnd != widget_hwnd:
            shell32.DragAcceptFiles(widget_hwnd, True)
        _allow_drop_messages(user32, hwnd)
        if hwnd != widget_hwnd:
            _allow_drop_messages(user32, widget_hwnd)
    except OSError as exc:
        logger.warning("Не удалось включить DragAcceptFiles: %s", exc)
        return False

    old_wndproc = get_long(hwnd, GWLP_WNDPROC)
    if not old_wndproc:
        logger.warning("GetWindowLongPtrW не вернул WNDPROC — DnD отключён")
        return False

    def _wndproc(hwnd_msg, msg, wparam, lparam):
        if msg == WM_DROPFILES:
            try:
                paths = list_hdrop_paths(shell32.DragQueryFileW, wparam)
            except OSError:
                paths = []
            try:
                shell32.DragFinish(wparam)
            except OSError:
                pass
            if paths:
                captured: Tuple[str, ...] = tuple(paths)
                try:
                    widget.after(0, lambda p=captured: callback(p))
                except Exception:
                    callback(captured)
            return 0
        return user32.CallWindowProcW(old_wndproc, hwnd_msg, msg, wparam, lparam)

    new_wndproc = WNDPROC(_wndproc)
    try:
        set_long(hwnd, GWLP_WNDPROC, ctypes.cast(new_wndproc, ctypes.c_void_p).value)
    except OSError as exc:
        logger.warning("Не удалось подменить WNDPROC для DnD: %s", exc)
        return False

    keep: dict = {
        "wndproc": new_wndproc,
        "old": old_wndproc,
        "hwnd": hwnd,
        "set_long": set_long,
    }
    widget._soc_file_drop = keep  # must outlive GC

    restored = {"done": False}

    def _restore(_event=None):
        if restored["done"]:
            return
        restored["done"] = True
        try:
            set_long(hwnd, GWLP_WNDPROC, old_wndproc)
        except OSError:
            pass

    try:
        widget.bind("<Destroy>", _restore, add="+")
    except Exception:
        pass
    return True
