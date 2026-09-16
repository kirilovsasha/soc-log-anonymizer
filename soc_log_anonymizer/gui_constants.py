"""Shared GUI constants (icons, sizes). No tkinter."""

UNDO_HISTORY_SIZE = 10
MIN_FONT_SIZE = 8
MAX_FONT_SIZE = 18
DEFAULT_FONT_SIZE = 10
AUTOSAVE_INTERVAL_MS = 30_000
GUI_DISPLAY_CHAR_LIMIT = 1_000_000
GUI_STATE_FILENAME = "soc_log_anonymizer_gui_state.json"

FONT_UI = "Segoe UI"
FONT_MONO = "Consolas"

PLACEHOLDER_FG = "_placeholder_"

# Status badge kinds for status_label (styled in _configure_styles).
_STATUS_KINDS = ("Idle", "Info", "Success", "Danger", "Warning", "Purple", "Muted")

# Single-codepoint emoji only — ZWJ / VS16 break width calc on some Windows fonts.
ICON_OPEN = "📁"
ICON_RUN = "⚡"
ICON_DEANON = "🔄"
ICON_UNDO = "↩"
ICON_COPY = "📋"
ICON_SAVE = "💾"
ICON_DIFF = "🔀"
ICON_STATS = "📊"
ICON_CLEAR = "🗑"
ICON_DICE = "🎲"
ICON_MOON = "🌙"
ICON_SEARCH = "🔍"
ICON_EXPORT = "📤"
ICON_LOCK = "🔐"
ICON_WARN = "⚠"
ICON_TAB_LOG = "📄"
ICON_TAB_MAP = "🗂"
ICON_TAB_CONFIG = "⚙"
