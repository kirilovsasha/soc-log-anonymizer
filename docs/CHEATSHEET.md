# Шпаргалка аналитика

Три команды:

```text
python -m soc_log_anonymizer anonymize -i raw.log -o clean.log --org bank --salt-file salt.txt --save-mapping mapping.json
python -m soc_log_anonymizer deanonymize -i llm.txt -o restored.txt --mapping mapping.json
python -m soc_log_anonymizer scan -i raw.log --salt-file salt.txt
```

Что обычно маскируется: USER, ORG, IP, EMAIL, FQDN, SID, UUID, MAC, PHONE, HASH (только рядом с hash/md5/sha/ntlm), SECRET/JWT.

Что не маскируется: пути (`/var/log/...`, `HTTP/1.1`, даты `2026/09/16`), well-known SID, nil GUID, значения из `allowlist`.

Выключить шум: в конфиге `skip_types: ["HASH", "PHONE"]` или `mask_types: ["USER", "ORG"]`.

Подробности: [FALSE_POSITIVES.md](FALSE_POSITIVES.md), [CUSTOM_PATTERNS.md](CUSTOM_PATTERNS.md).
