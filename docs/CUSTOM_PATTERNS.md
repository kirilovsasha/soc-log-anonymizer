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

- `strategy`: `full` (псевдоним), `partial` (края видны), `format` (A/9).
- `priority`: больше — раньше.
- Проверка: `python -m soc_log_anonymizer validate-config my.json`.
- Не кладите сюда вендорский «профиль на все случаи»: один паттерн — одна сущность.

Семьи `mask_types`/`skip_types` на custom не действуют: custom всегда opt-in.
