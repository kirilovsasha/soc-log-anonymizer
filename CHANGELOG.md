# Changelog

## Unreleased

- GUI: removed the dedicated Allowlist list/text editor; exceptions are edited
  only in the main JSON config (`"allowlist"`), which also accepts a plain
  text block (newlines and/or commas) in addition to a string array.
- GUI: «Очистить всё» is on the main toolbar; removed from the «Ещё» menu.

## 2.4.0

- Expanded golden corpus with Fortinet / Palo Alto / su-initiator / Azure /
  AWS / Windows Event JSON cases; added FP/FN scoring tests.
- AUTH patterns: su initiator (`'su root' failed for X on`), Fortinet quoted
  user/login, Palo Alto `from user` / `User … failed`.
- Default JSON keys/hints for Azure AD, AWS CloudTrail, Windows Event fields.
- Deterministic collision-suffix merge after `--workers` / `batch --workers`.
- `--stream` accumulates pretty-printed multi-line JSON documents.
- Optional mapping encryption: `--mapping-passphrase` / `--mapping-dpapi`.
- GUI split into mixin modules (`gui_*_mixin.py`); `gui.py` is a thin shell.
- `pip install -e ".[dev]"` extras; CI lint/typecheck on full package;
  benchmark job; GitHub Release + PyPI publish workflows.
- README shortened; full reference moved to `docs/REFERENCE.md`.

## 2.3.0

- Windows EXE packaging: **onefile** GUI+CLI (primary), optional onedir,
  PE version/icon, DPI hook, default config bundle, `build_windows.bat`,
  Windows CI artifacts.
- GUI: crash log + MessageBox for windowed builds, AppData/portable data
  paths, draft autosave toggle, open app/data/crash folders, large-file
  preview+sidecar defaults.
- Security: Windows ACL (`icacls`) for salt/mapping/drafts; docs
  `docs/WINDOWS_EXE.md`.
- Fixed Windows CLI crash (`UnicodeEncodeError`) when printing Cyrillic messages on cp1252 consoles (also CI on `windows-latest`).
- Fixed GUI highlight falsely marking allowlisted tokens (e.g. `administrator`) when a shorter mapped value like `admin` was a substring.
- Compacted the GUI header into a single toolbar row; secondary actions live under «Ещё», theme/font/sync under «Вид».
- `org_name` is config-only (toolbar field removed); Copy result is on the main toolbar.
- Split GUI into `gui_constants`, `gui_layout`, `gui_profiles`, `gui_diff_html` modules.
- Added a list-based allowlist editor on the Config tab (no source profiles).
- Removed GUI session fields `mask_types` / `skip_types` / `allowlist`; `allowlist` remains config-only.
- Removed `mask_types` and `skip_types` configuration options entirely.

## 2.2.0

- Removed generic PATH masking; protocol/date/cipher slashes stay intact.
- Added `mask_types`, `skip_types`, `allowlist`, stricter HASH/FQDN/PHONE/USER filters,
  JSON compact preservation, multiline join, RFC5424 host split, and `anonymize_result()`.
- GUI: Scan preview, session mask/skip/allowlist fields, mapping type filter and jump-to-value,
  large-file sidecar output; theme constants extracted to `gui_theme.py`.
- Docs: analyst cheat sheet, false-positive catalog, custom-pattern guide; golden corpus tests.
- Stopped masking filesystem paths as `PATH`. The old `/`-anywhere regex
  treated protocol versions, dates, and cipher suites (`HTTP/1.1`,
  `2026/09/16`, `IKEv2/AES256`) as paths. Usernames in home directories
  (`C:\Users\jdoe`, `/home/jdoe`, `/Users/jdoe`) are still masked as `USER`.
- Added scan reports in JSONL, JSON, and CSV formats with file sizes,
  replacement counts, line counts, changed-line positions, safety status,
  timing, and cache metrics.
- Added `batch --dry-run` and optional JSON progress events.
- Added `diff-config` and `validate-config --fix`.
- Added opt-in custom regex patterns/types in configuration.
- Added GUI file ordering/removal, folder import, and cancellation.
- Added encoding-corruption warnings and documentation/example checks.

## 2.1.0

- Existing stable anonymization, streaming, mapping compatibility, GUI,
  and CLI behavior.
