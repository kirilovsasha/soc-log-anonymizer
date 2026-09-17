# Каталог ложных срабатываний

| Симптом | Почему | Что сделано / что настроить |
|---|---|---|
| `HTTP/1.1`, `2026/09/16`, `IKEv2/AES256` становились `[PATH_…]` | Regex на любой `/` | Тип PATH убран. Пути не маскируются. |
| `Windows\System32` как `[USER_…]` | Формат `DOMAIN\user` | Сегменты после `\` и имена Windows/System32/Users пропускаются. |
| Случайный 32-hex request-id как HASH | Любой hex длины 32/40/64 | HASH в свободном тексте только рядом с hash/md5/sha/ntlm (`hash_require_context`). |
| `for.local` как FQDN | TLD `local` + стоп-слово | Первая метка из `fqdn_stopwords` не маскируется. |
| `verify()` красный на безобидном hex | Gatekeeper = те же regex + residual | Те же фильтры, что и у замены; residual ловит email/`DOMAIN\user`/УНП/PAN. Отключить: `"residual_scan": false`. |
| Компактный JSON разъезжался | Всегда `indent=2` | `json_preserve_formatting`: однострочный JSON остаётся однострочным. |
| Слишком «дырявый» телефон/карта | `mask_strategies` partial | Полное скрытие: `"mask_strategies": {"PHONE": "full", "PAN": "full"}`. |

Allowlist (не маскировать): в основном JSON-конфиге поле `"allowlist"` —
массив строк или текст через переносы/запятые, например
`"allowlist": ["8.8.8.8", "Administrator"]` или
`"allowlist": "8.8.8.8\nAdministrator"`.
