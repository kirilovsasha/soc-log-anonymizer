# Шифрование файла соответствия (mapping)

Файлы mapping содержат соль и пары «исходное значение → псевдоним» и
так же чувствительны, как сами исходные логи. По умолчанию сохранение
остаётся **обычным JSON с правами 0600 / Windows ACL**.

Опциональное шифрование (только стандартная библиотека):

## Парольная фраза (кроссплатформенно)

```bash
python -m soc_log_anonymizer anonymize -i raw.log -o clean.log \
  --salt-file salt.txt --save-mapping mapping.json \
  --mapping-passphrase "correct horse battery"

python -m soc_log_anonymizer deanonymize -i reply.txt -o out.txt \
  --mapping mapping.json --mapping-passphrase "correct horse battery"
```

Или через переменную окружения:

```bash
# Windows (cmd)
set SOC_MAP_PASS=...
python -m soc_log_anonymizer anonymize ... --save-mapping m.json \
  --mapping-passphrase-env SOC_MAP_PASS

# Linux / macOS
export SOC_MAP_PASS=...
python -m soc_log_anonymizer anonymize ... --save-mapping m.json \
  --mapping-passphrase-env SOC_MAP_PASS
```

Конверт: PBKDF2-HMAC-SHA256 (по умолчанию 600 000 итераций) + SHA-256
keystream XOR + HMAC для целостности. Число итераций для тестов можно
переопределить через `SOC_ANON_MAPPING_KDF_ITERATIONS`.

## Windows DPAPI

```bash
python -m soc_log_anonymizer anonymize ... --save-mapping m.json --mapping-dpapi
python -m soc_log_anonymizer deanonymize ... --mapping m.json
```

Расшифровка возможна только тем же пользователем Windows на той же
машине (DPAPI).

## Библиотека

```python
anon.save_mapping("m.json", passphrase="...")
anon.save_mapping("m.json", use_dpapi=True)
SOCLogAnonymizer.load_mapping("m.json", passphrase="...")
```

Основной контроль — шифрование диска и ограниченные ACL; этот слой
замедляет случайную утечку украденного mapping-файла.
