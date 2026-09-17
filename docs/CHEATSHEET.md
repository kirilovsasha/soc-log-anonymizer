# Шпаргалка аналитика

Порядок работы end-to-end (GUI/CLI, salt/mapping, чеклист LLM):
[RUNBOOK.md](RUNBOOK.md).

Три команды:

```text
python -m soc_log_anonymizer anonymize -i raw.log -o clean.log --org bank --salt-file salt.txt --save-mapping mapping.json
python -m soc_log_anonymizer deanonymize -i llm.txt -o restored.txt --mapping mapping.json
python -m soc_log_anonymizer scan -i raw.log --salt-file salt.txt
```

Шифрованный mapping (опционально):

```text
python -m soc_log_anonymizer anonymize ... --save-mapping mapping.json --mapping-passphrase "секрет"
python -m soc_log_anonymizer deanonymize ... --mapping mapping.json --mapping-passphrase "секрет"
```

Что обычно маскируется: USER, ORG, IP, EMAIL, FQDN, SID, UUID, MAC, PHONE,
HASH (только рядом с hash/md5/sha/ntlm), SECRET/JWT, **УНП / PAN / IBAN BY /
личный номер** (РБ), quoted `user="…"`.

Стратегии по умолчанию: PHONE/PAN/IBAN — `partial` (края видны); УНП — `full`.
Перед отправкой в LLM: `anonymize --fail-on-unsafe` (включает residual-скан).

Что не маскируется: пути (`/var/log/...`, `HTTP/1.1`, даты `2026/09/16`),
well-known SID, nil GUID, значения из `allowlist` в конфиге, ФИО в свободном тексте.

Windows EXE подхватывает `soc_log_anonymizer.json` рядом с exe (из
`packaging/default_config.json` при сборке) — для РБ там уже `+375`/`80xx` и `.by`.

Подробности: [FALSE_POSITIVES.md](FALSE_POSITIVES.md),
[CUSTOM_PATTERNS.md](CUSTOM_PATTERNS.md),
[MAPPING_ENCRYPTION.md](MAPPING_ENCRYPTION.md).
