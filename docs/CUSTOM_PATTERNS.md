# Свой regex без правки anonymizer.py

В `soc_log_anonymizer.json`:

```json
{
  "custom_patterns": {
    "TICKET": {
      "pattern": "TCK-[0-9]{4,}",
      "type": "TICKET",
      "strategy": "full",
      "priority": 10,
      "enabled": true,
      "test_string": "TCK-1234"
    }
  }
}
```

| Поле | Смысл |
|---|---|
| `strategy` | `full` — целиком псевдоним; `partial` — края видны; `format` — форма A/9 |
| `priority` | Чем больше, тем раньше срабатывает |
| `enabled` | `false` — временно выключить без удаления |
| `test_string` | Строка для `validate-config` (проверка, что паттерн матчится) |

Проверка: `python -m soc_log_anonymizer validate-config my.json`.

Не кладите сюда вендорский «профиль на все случаи»: один паттерн — одна
сущность. Для УНП/PAN/IBAN/личного номера РБ встроенные типы уже есть —
см. [REFERENCE.md](REFERENCE.md#masked-data).
