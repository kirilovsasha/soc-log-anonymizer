# Mapping file encryption

Mapping files contain salt + original→pseudonym pairs and are as sensitive
as the source logs. Default save mode remains **plain JSON with 0600/ACL**.

Optional encryption (stdlib only):

## Passphrase (cross-platform)

```bash
python -m soc_log_anonymizer anonymize -i raw.log -o clean.log \
  --salt-file salt.txt --save-mapping mapping.json \
  --mapping-passphrase "correct horse battery"

python -m soc_log_anonymizer deanonymize -i reply.txt -o out.txt \
  --mapping mapping.json --mapping-passphrase "correct horse battery"
```

Or via env:

```bash
set SOC_MAP_PASS=...
python -m soc_log_anonymizer anonymize ... --save-mapping m.json \
  --mapping-passphrase-env SOC_MAP_PASS
```

Envelope uses PBKDF2-HMAC-SHA256 (600 000 iterations by default) + SHA-256
keystream XOR + HMAC integrity. Override iterations for tests with
`SOC_ANON_MAPPING_KDF_ITERATIONS`.

## Windows DPAPI

```bash
python -m soc_log_anonymizer anonymize ... --save-mapping m.json --mapping-dpapi
python -m soc_log_anonymizer deanonymize ... --mapping m.json
```

Decrypts only for the same Windows user on the same machine (DPAPI).

## Library

```python
anon.save_mapping("m.json", passphrase="...")
anon.save_mapping("m.json", use_dpapi=True)
SOCLogAnonymizer.load_mapping("m.json", passphrase="...")
```

Prefer full-disk encryption and restricted ACLs as the primary control;
this layer slows casual disclosure of a stolen mapping file.
