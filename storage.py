"""
storage.py — Storage Module
Secret: physical file format (encrypted JSON), file paths, and key bootstrap strategy.
All callers receive/send plain Python dicts; they never touch the filesystem directly.
"""

import json
import os
import stat

import crypto

# File locations (relative to working directory)
DB_FILE    = '.aba_db'    # AES-256-GCM encrypted JSON blob
KEY_FILE   = '.aba_key'  # 256-bit raw key, chmod 600
AUDIT_FILE = '.aba_audit' # protected separately by audit_logger

DB_KEY_ID = 'db_master'

# ── Exit codes ────────────────────────────────────────────────────────────────
STORE_OK             = 'STORE_OK'
STORE_NOT_FOUND      = 'STORE_NOT_FOUND'
STORE_CORRUPTED      = 'STORE_CORRUPTED'
STORE_PERMISSION_DENIED = 'STORE_PERMISSION_DENIED'
STORE_ERROR          = 'STORE_ERROR'


def storage_init_key():
    """
    Load the database encryption key from disk, or generate and persist a fresh one.
    Idempotent: safe to call if key already loaded in memory.
    """
    if crypto.crypto_get_key_bytes(DB_KEY_ID) is not None:
        return   # already loaded
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, 'rb') as f:
                key_bytes = f.read()
            crypto.crypto_load_key(DB_KEY_ID, key_bytes)
        except Exception:
            raise RuntimeError("Failed to load encryption key. Database may be inaccessible.")
    else:
        code = crypto.crypto_generate_key(DB_KEY_ID)
        if code != crypto.CRYPTO_OK:
            raise RuntimeError("Failed to generate encryption key.")
        key_bytes = crypto.crypto_get_key_bytes(DB_KEY_ID)
        _write_protected(KEY_FILE, key_bytes, binary=True)


def storage_read_db():
    """Returns (db_dict, exit_code)."""
    if not os.path.exists(DB_FILE):
        return None, STORE_NOT_FOUND
    try:
        with open(DB_FILE, 'rb') as f:
            ciphertext = f.read()
        plaintext, code = crypto.crypto_decrypt(ciphertext, DB_KEY_ID)
        if code != crypto.CRYPTO_OK:
            return None, STORE_CORRUPTED
        return json.loads(plaintext.decode('utf-8')), STORE_OK
    except json.JSONDecodeError:
        return None, STORE_CORRUPTED
    except Exception:
        return None, STORE_ERROR


def storage_write_db(db_object: dict):
    """Encrypts and persists the database. Returns exit_code."""
    try:
        plaintext = json.dumps(db_object, indent=2).encode('utf-8')
        ciphertext, code = crypto.crypto_encrypt(plaintext, DB_KEY_ID)
        if code != crypto.CRYPTO_OK:
            return STORE_ERROR
        _write_protected(DB_FILE, ciphertext, binary=True)
        return STORE_OK
    except PermissionError:
        return STORE_PERMISSION_DENIED
    except Exception:
        return STORE_ERROR


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_protected(path: str, data, binary: bool = False):
    """Write data to path and enforce 600 permissions (owner r/w only)."""
    mode = 'wb' if binary else 'w'
    with open(path, mode) as f:
        f.write(data)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)