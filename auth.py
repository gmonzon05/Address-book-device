"""
auth.py — Auth Module
Secret: session representation, lockout counter storage, hashing rounds,
        first-login state machine, and session token format.
Callers see only integer result codes and boolean query methods.
"""

import time

import crypto
import storage
import audit_logger as al

MAX_FAILED_ATTEMPTS = 3
SESSION_TIMEOUT_SEC = 600   # 10 minutes (SEC-6, PR-9)

# ── In-memory session state (single active session) ───────────────────────────
_session = {
    'user':          None,
    'last_activity': None,
    'token':         None,
    'force_change':  False,   # set when RPW or first login requires new password
}

# ── Result codes ──────────────────────────────────────────────────────────────
AUTH_OK                  = 0
AUTH_ALREADY_LOGGED_IN   = 1
AUTH_INVALID_CREDENTIALS = 2
AUTH_ACCOUNT_LOCKED      = 3
AUTH_FIRST_LOGIN         = 4   # must set new password before any other command
AUTH_NO_SESSION          = 5
AUTH_EXPIRED             = 6
AUTH_PASSWORDS_NO_MATCH  = 7
AUTH_ILLEGAL_CHARS       = 8
AUTH_WEAK_PASSWORD       = 9
AUTH_ERROR               = 10


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_db():
    db, _ = storage.storage_read_db()
    return db

def _save_db(db):
    storage.storage_write_db(db)

def _touch():
    """Update last-activity timestamp."""
    _session['last_activity'] = time.time()

def _clear_session():
    _session['user']          = None
    _session['last_activity'] = None
    _session['token']         = None
    _session['force_change']  = False


# ── Public interface ──────────────────────────────────────────────────────────

def auth_login(user_id: str, password: str) -> int:
    """
    Authenticate user_id with password.
    Returns AUTH_FIRST_LOGIN if account has no password yet or force_change is set.
    """
    if _session['user']:
        return AUTH_ALREADY_LOGGED_IN

    db = _load_db()
    if user_id not in db['users']:
        al.audit_log(al.EVT_LOGIN_FAIL, user_id, 'user not found')
        return AUTH_INVALID_CREDENTIALS

    user = db['users'][user_id]

    if user.get('locked', False):
        al.audit_log(al.EVT_LOGIN_FAIL, user_id, 'account locked')
        return AUTH_ACCOUNT_LOCKED

    # First login: no password has ever been set
    if user['password_hash'] is None:
        token_bytes, _ = crypto.crypto_secure_random(32)
        _session['user']          = user_id
        _session['last_activity'] = time.time()
        _session['token']         = token_bytes.hex()
        _session['force_change']  = True
        al.audit_log(al.EVT_LOGIN_FIRST, user_id)
        return AUTH_FIRST_LOGIN

    # Normal login: verify password
    match, _ = crypto.crypto_verify_password(password, user['password_hash'])
    if not match:
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
        if user['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
            user['locked'] = True
            al.audit_log(al.EVT_LOGIN_FAIL, user_id, 'account locked after max attempts')
        else:
            al.audit_log(al.EVT_LOGIN_FAIL, user_id,
                         f"attempt {user['failed_attempts']}/{MAX_FAILED_ATTEMPTS}")
        _save_db(db)
        return AUTH_INVALID_CREDENTIALS

    # Success
    user['failed_attempts'] = 0
    _save_db(db)

    token_bytes, _ = crypto.crypto_secure_random(32)
    _session['user']          = user_id
    _session['last_activity'] = time.time()
    _session['token']         = token_bytes.hex()
    _session['force_change']  = user.get('force_change', False)

    al.audit_log(al.EVT_LOGIN_SUCCESS, user_id)

    if _session['force_change']:
        return AUTH_FIRST_LOGIN   # forced change (post-RPW)

    return AUTH_OK


def auth_logout() -> int:
    """Invalidate session immediately (SR-5, REQ-LGO)."""
    if not _session['user']:
        return AUTH_NO_SESSION
    user = _session['user']
    _clear_session()
    al.audit_log(al.EVT_LOGOUT, user)
    return AUTH_OK


def auth_check_session_timeout() -> int:
    """
    Call before every command that requires auth.
    Returns AUTH_EXPIRED and force-logs out if inactive > SESSION_TIMEOUT_SEC.
    """
    if not _session['user']:
        return AUTH_NO_SESSION
    if time.time() - _session['last_activity'] > SESSION_TIMEOUT_SEC:
        user = _session['user']
        _clear_session()
        al.audit_log(al.EVT_SESSION_TIMEOUT, user)
        return AUTH_EXPIRED
    _touch()
    return AUTH_OK


def auth_change_password(old_password: str, new_password: str,
                         confirm_password: str, skip_old_check: bool = False) -> int:
    """
    Change the active user's password.
    skip_old_check=True is used for first-login and forced-change flows where
    the user has already been authenticated by auth_login.
    """
    if not _session['user']:
        return AUTH_NO_SESSION

    db     = _load_db()
    user   = db['users'][_session['user']]

    # Verify old password unless this is a first-login or forced-change flow
    if not skip_old_check and user['password_hash'] is not None:
        match, _ = crypto.crypto_verify_password(old_password, user['password_hash'])
        if not match:
            al.audit_log(al.EVT_PW_CHANGE_FAIL, _session['user'], 'wrong old password')
            return AUTH_INVALID_CREDENTIALS

    if new_password != confirm_password:
        return AUTH_PASSWORDS_NO_MATCH

    strong, reason, _ = crypto.crypto_check_password_strength(new_password)
    if not strong:
        # Distinguish illegal-chars vs complexity (return codes match SRS exception cases)
        if 'illegal' in (reason or '').lower():
            return AUTH_ILLEGAL_CHARS
        return AUTH_WEAK_PASSWORD

    new_hash, code = crypto.crypto_hash_password(new_password)
    if code != crypto.CRYPTO_OK:
        return AUTH_ERROR

    user['password_hash'] = new_hash
    user['force_change']  = False
    _save_db(db)
    _session['force_change'] = False
    al.audit_log(al.EVT_PW_CHANGE_OK, _session['user'])
    return AUTH_OK


def auth_verify_password(password: str) -> int:
    """
    Re-authenticate the active user without creating a new session (SR-6).
    Required before all admin write actions.
    """
    if not _session['user']:
        return AUTH_NO_SESSION
    db   = _load_db()
    user = db['users'][_session['user']]
    if user['password_hash'] is None:
        return AUTH_INVALID_CREDENTIALS
    match, _ = crypto.crypto_verify_password(password, user['password_hash'])
    if not match:
        al.audit_log(al.EVT_REAUTH_FAIL, _session['user'])
        return AUTH_INVALID_CREDENTIALS
    al.audit_log(al.EVT_REAUTH_OK, _session['user'])
    _touch()
    return AUTH_OK


# ── Session query methods ─────────────────────────────────────────────────────

def auth_is_authenticated() -> bool:
    return _session['user'] is not None

def auth_get_active_user() -> str | None:
    return _session['user']

def auth_is_admin() -> bool:
    return _session['user'] == 'admin'

def auth_needs_force_change() -> bool:
    return _session.get('force_change', False)