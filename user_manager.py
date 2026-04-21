"""
user_manager.py — User Manager Module
Secret: internal account record schema, indexing, metadata fields,
        and userID validation rules.
Callers work only through add/delete/list/reset operations.
"""

import re

import storage
import audit_logger as al
import crypto

MAX_USERS       = 7    # max non-admin accounts (SRS limits)
_USERID_RE      = re.compile(r'^[a-zA-Z0-9]{1,16}$')

# ── Result codes ──────────────────────────────────────────────────────────────
USR_OK                  = 0
USR_NO_SESSION          = 1
USR_UNAUTHORIZED        = 2
USR_INVALID_FORMAT      = 3
USR_EXISTS              = 4
USR_NOT_FOUND           = 4   # same slot — context distinguishes add vs delete
USR_MAX_USERS           = 5
USR_CANNOT_DEL_SELF     = 5   # same slot — context distinguishes
USR_CANNOT_DEL_LAST_ADMIN = 6
USR_WEAK_PASSWORD       = 5   # for RPW
USR_CANNOT_RESET_SELF   = 7
USR_ERROR               = 99


def _load_db():
    db, _ = storage.storage_read_db()
    return db

def _save_db(db):
    storage.storage_write_db(db)


# ── Public interface ──────────────────────────────────────────────────────────

def users_add(admin_user: str, user_id: str) -> int:
    """
    Create a new user account with no password (first-login flow handles password).
    Requires prior re-authentication (enforced by CLI before this call).
    """
    if not _USERID_RE.match(user_id):
        return USR_INVALID_FORMAT

    db = _load_db()

    if user_id in db['users']:
        return USR_EXISTS

    non_admin_count = sum(1 for u in db['users'] if u != 'admin')
    if non_admin_count >= MAX_USERS:
        return USR_MAX_USERS

    db['users'][user_id] = {
        'password_hash':  None,
        'role':           'user',
        'force_change':   True,
        'failed_attempts': 0,
        'locked':         False,
    }
    db['records'][user_id] = {}
    _save_db(db)
    al.audit_log(al.EVT_USER_ADD, admin_user, f'created user {user_id}')
    return USR_OK


def users_delete(admin_user: str, user_id: str) -> int:
    """
    Delete account and cascade-delete all associated records (REQ-RMU).
    Cannot delete self or the last admin.
    """
    if not _USERID_RE.match(user_id):
        return USR_INVALID_FORMAT

    db = _load_db()

    if user_id not in db['users']:
        return USR_NOT_FOUND

    if user_id == admin_user:
        return USR_CANNOT_DEL_SELF

    if user_id == 'admin':
        return USR_CANNOT_DEL_LAST_ADMIN

    del db['users'][user_id]
    db['records'].pop(user_id, None)
    _save_db(db)
    al.audit_log(al.EVT_USER_DEL, admin_user, f'deleted user {user_id}')
    return USR_OK


def users_list(admin_user: str) -> tuple[list, int]:
    """Return (list_of_userIDs, result_code). Admin account excluded from list."""
    db = _load_db()
    users = sorted(uid for uid in db['users'] if uid != 'admin')
    al.audit_log(al.EVT_LIST_USERS, admin_user)
    return users, USR_OK


def users_exists(user_id: str) -> bool:
    db = _load_db()
    return user_id in db['users']


def users_reset_password(admin_user: str, target_user: str, new_password: str) -> int:
    """
    Admin resets another user's password and sets force_change flag (REQ-RPW).
    Admin must use CHP to change their own password.
    """
    if target_user == admin_user:
        return USR_CANNOT_RESET_SELF

    db = _load_db()

    if target_user not in db['users']:
        return USR_NOT_FOUND

    strong, _, _ = crypto.crypto_check_password_strength(new_password)
    if not strong:
        return USR_WEAK_PASSWORD

    new_hash, code = crypto.crypto_hash_password(new_password)
    if code != crypto.CRYPTO_OK:
        return USR_ERROR

    db['users'][target_user]['password_hash'] = new_hash
    db['users'][target_user]['force_change']  = True
    _save_db(db)
    al.audit_log(al.EVT_PW_RESET, admin_user, f'reset password for {target_user}')
    return USR_OK