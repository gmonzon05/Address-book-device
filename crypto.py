"""
crypto.py — Crypto Module
Secret: algorithm choices, Argon2id parameters, key storage format, AES nonce scheme.
All other modules call clean functions; none know what algorithm is running underneath.
"""

import os
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id parameters (SRS technical constraints: 64 MB memory, 3 iterations)
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MB in KiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

# Runtime key store — keys never written here to disk; bytes only in memory
_keys: dict[str, bytes] = {}

# Password complexity rules (hidden from all callers)
_MIN_LEN = 8
_MAX_LEN = 24
_ALLOWED_SPECIAL = set('!@#$%^&*()_+-=[]{}|;:,.<>?')


# ── Exit codes ────────────────────────────────────────────────────────────────
CRYPTO_OK                = 'CRYPTO_OK'
CRYPTO_ERROR             = 'CRYPTO_ERROR'
CRYPTO_INVALID_INPUT     = 'CRYPTO_INVALID_INPUT'
CRYPTO_KEY_NOT_FOUND     = 'CRYPTO_KEY_NOT_FOUND'
CRYPTO_KEY_EXISTS        = 'CRYPTO_KEY_EXISTS'
CRYPTO_DECRYPTION_FAILED = 'CRYPTO_DECRYPTION_FAILED'
CRYPTO_WEAK_PASSWORD     = 'CRYPTO_WEAK_PASSWORD'
CRYPTO_HASH_MISMATCH     = 'CRYPTO_HASH_MISMATCH'


# ── Password hashing ──────────────────────────────────────────────────────────

def crypto_hash_password(plaintext: str):
    """Return (encoded_hash_str, exit_code). Salt is embedded in the hash string."""
    if not plaintext:
        return None, CRYPTO_INVALID_INPUT
    try:
        return _ph.hash(plaintext), CRYPTO_OK
    except Exception:
        return None, CRYPTO_ERROR


def crypto_verify_password(plaintext: str, stored_hash: str):
    """Constant-time comparison. Returns (match: bool, exit_code)."""
    if not plaintext or not stored_hash:
        return False, CRYPTO_INVALID_INPUT
    try:
        result = _ph.verify(stored_hash, plaintext)
        return result, CRYPTO_OK
    except (VerifyMismatchError, VerificationError):
        return False, CRYPTO_HASH_MISMATCH
    except InvalidHashError:
        return False, CRYPTO_INVALID_INPUT
    except Exception:
        return False, CRYPTO_ERROR


# ── Symmetric encryption (AES-256-GCM) ───────────────────────────────────────

def crypto_encrypt(plaintext: bytes, key_id: str):
    """Returns (ciphertext: bytes, exit_code). Ciphertext = nonce || tag+ciphertext."""
    if key_id not in _keys:
        return None, CRYPTO_KEY_NOT_FOUND
    if plaintext is None:
        return None, CRYPTO_INVALID_INPUT
    try:
        nonce = os.urandom(12)           # 96-bit nonce, fresh per call
        aesgcm = AESGCM(_keys[key_id])
        ct = aesgcm.encrypt(nonce, plaintext, None)  # tag appended by library
        return nonce + ct, CRYPTO_OK
    except Exception:
        return None, CRYPTO_ERROR


def crypto_decrypt(ciphertext: bytes, key_id: str):
    """Returns (plaintext: bytes, exit_code). Verifies GCM tag — detects tampering."""
    if key_id not in _keys:
        return None, CRYPTO_KEY_NOT_FOUND
    if not ciphertext or len(ciphertext) < 12:
        return None, CRYPTO_INVALID_INPUT
    try:
        nonce = ciphertext[:12]
        ct    = ciphertext[12:]
        aesgcm = AESGCM(_keys[key_id])
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return plaintext, CRYPTO_OK
    except Exception:
        return None, CRYPTO_DECRYPTION_FAILED


# ── Key management ────────────────────────────────────────────────────────────

def crypto_generate_key(key_id: str):
    """Generate and register a fresh 256-bit key. Refuses to overwrite."""
    if key_id in _keys:
        return CRYPTO_KEY_EXISTS
    _keys[key_id] = AESGCM.generate_key(bit_length=256)
    return CRYPTO_OK


def crypto_load_key(key_id: str, key_bytes: bytes):
    """Load a pre-existing key from persistent storage into the runtime store."""
    _keys[key_id] = key_bytes
    return CRYPTO_OK


def crypto_get_key_bytes(key_id: str):
    """Return raw key bytes (used only by Storage module to persist the key)."""
    return _keys.get(key_id)


def crypto_delete_key(key_id: str):
    """Zero out and remove a key from memory."""
    if key_id not in _keys:
        return CRYPTO_KEY_NOT_FOUND
    length = len(_keys[key_id])
    _keys[key_id] = bytes(length)   # overwrite before GC
    del _keys[key_id]
    return CRYPTO_OK


# ── Secure utilities ──────────────────────────────────────────────────────────

def crypto_secure_random(num_bytes: int):
    """Returns (data: bytes, exit_code) from OS CSPRNG."""
    if num_bytes <= 0:
        return None, CRYPTO_INVALID_INPUT
    return os.urandom(num_bytes), CRYPTO_OK


def crypto_constant_time_compare(a: bytes, b: bytes):
    """Constant-time byte comparison to prevent timing attacks."""
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        return False, CRYPTO_INVALID_INPUT
    return hmac.compare_digest(a, b), CRYPTO_OK


# ── Password strength ─────────────────────────────────────────────────────────

def crypto_check_password_strength(password: str):
    """
    Returns (strong: bool, reason: str | None, exit_code).
    Rules are hidden from callers.
    """
    if not password:
        return False, "Password cannot be empty", CRYPTO_OK
    if len(password) < _MIN_LEN:
        return False, f"Password must be at least {_MIN_LEN} characters", CRYPTO_OK
    if len(password) > _MAX_LEN:
        return False, f"Password must be at most {_MAX_LEN} characters", CRYPTO_OK

    allowed_chars = (set('abcdefghijklmnopqrstuvwxyz') |
                     set('ABCDEFGHIJKLMNOPQRSTUVWXYZ') |
                     set('0123456789') | _ALLOWED_SPECIAL)
    for ch in password:
        if ch not in allowed_chars:
            return False, "Password contains illegal characters", CRYPTO_OK

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter", CRYPTO_OK
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter", CRYPTO_OK
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit", CRYPTO_OK

    return True, None, CRYPTO_OK