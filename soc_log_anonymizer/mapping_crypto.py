"""Optional mapping-file encryption (stdlib only).

Formats
-------
* Plain JSON — unchanged ``schema_version`` 1 payload.
* Passphrase — envelope ``schema_version`` 2 with PBKDF2-derived keystream
  XOR + HMAC-SHA256 integrity (no third-party crypto libs).
* Windows DPAPI — same envelope; ciphertext from ``CryptProtectData`` via
  ctypes (Windows only).

Threat model: slows casual disclosure of a mapping file at rest. Prefer
OS disk encryption and ``0600``/ACL for primary protection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from typing import Any, Dict, Optional, Tuple

_ENVELOPE_VERSION = 2
_KDF_ITERATIONS = 600_000
_SALT_LEN = 16
_NONCE_LEN = 16


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """SHA-256 counter mode keystream (stdlib-only stream cipher)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def _derive_keys(passphrase: str, salt: bytes, iterations: int = _KDF_ITERATIONS) -> Tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=64,
    )
    return material[:32], material[32:]


def encrypt_with_passphrase(
    plaintext: bytes,
    passphrase: str,
    *,
    iterations: int = _KDF_ITERATIONS,
) -> Dict[str, Any]:
    salt = secrets.token_bytes(_SALT_LEN)
    nonce = secrets.token_bytes(_NONCE_LEN)
    enc_key, mac_key = _derive_keys(passphrase, salt, iterations)
    ciphertext = _xor(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).hexdigest()
    return {
        "schema_version": _ENVELOPE_VERSION,
        "encryption": "passphrase-hmac-sha256",
        "kdf": "pbkdf2-hmac-sha256",
        "kdf_iterations": iterations,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "mac": tag,
    }


def decrypt_with_passphrase(envelope: Dict[str, Any], passphrase: str) -> bytes:
    salt = bytes.fromhex(envelope["salt"])
    nonce = bytes.fromhex(envelope["nonce"])
    ciphertext = bytes.fromhex(envelope["ciphertext"])
    iterations = int(envelope.get("kdf_iterations") or _KDF_ITERATIONS)
    enc_key, mac_key = _derive_keys(passphrase, salt, iterations)
    expected = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(envelope.get("mac", ""))):
        raise ValueError("Mapping MAC verification failed (wrong passphrase or corrupt file)")
    return _xor(ciphertext, _keystream(enc_key, nonce, len(ciphertext)))


def _dpapi_protect(data: bytes) -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("DPAPI encryption is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    blob_in = DATA_BLOB(len(data), ctypes.create_string_buffer(data, len(data)))
    blob_out = DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out),
    ):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("DPAPI decryption is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    blob_in = DATA_BLOB(len(data), ctypes.create_string_buffer(data, len(data)))
    blob_out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out),
    ):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def encrypt_with_dpapi(plaintext: bytes) -> Dict[str, Any]:
    ciphertext = _dpapi_protect(plaintext)
    return {
        "schema_version": _ENVELOPE_VERSION,
        "encryption": "dpapi",
        "ciphertext": ciphertext.hex(),
    }


def decrypt_with_dpapi(envelope: Dict[str, Any]) -> bytes:
    return _dpapi_unprotect(bytes.fromhex(envelope["ciphertext"]))


def wrap_payload(
    payload: Dict[str, Any],
    *,
    passphrase: Optional[str] = None,
    use_dpapi: bool = False,
    iterations: int = _KDF_ITERATIONS,
) -> Dict[str, Any]:
    """Return either the plain payload or an encrypted envelope."""
    if use_dpapi and passphrase:
        raise ValueError("Choose either passphrase or DPAPI, not both")
    if not passphrase and not use_dpapi:
        return payload
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if use_dpapi:
        return encrypt_with_dpapi(raw)
    assert passphrase is not None
    return encrypt_with_passphrase(raw, passphrase, iterations=iterations)


def unwrap_payload(
    data: Dict[str, Any],
    *,
    passphrase: Optional[str] = None,
) -> Dict[str, Any]:
    """Decode plain or encrypted mapping JSON object."""
    enc = data.get("encryption")
    if not enc:
        return data
    if enc == "passphrase-hmac-sha256":
        if not passphrase:
            raise ValueError("Encrypted mapping requires a passphrase")
        raw = decrypt_with_passphrase(data, passphrase)
    elif enc == "dpapi":
        raw = decrypt_with_dpapi(data)
    else:
        raise ValueError(f"Unsupported mapping encryption: {enc!r}")
    return json.loads(raw.decode("utf-8"))


def is_encrypted_mapping_file(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return bool(isinstance(data, dict) and data.get("encryption"))
    except (OSError, json.JSONDecodeError, TypeError):
        return False
