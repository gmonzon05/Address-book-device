"""
audit_logger.py — Audit Logger Module
Secret: event schema, file format, rotation policy, and tamper-evidence strategy.
Callers emit named event types; they never touch the log file directly.
"""

import csv
import os
import stat
from datetime import datetime

AUDIT_FILE  = '.aba_audit'
MAX_RECORDS = 512   # FIFO: oldest evicted when full (SRS limits)

# ── Event type constants (used by all modules) ────────────────────────────────
EVT_LOGIN_SUCCESS   = 'LS'    # successful login
EVT_LOGIN_FAIL      = 'LF'    # failed login attempt
EVT_LOGIN_FIRST     = 'L1'    # first-login password creation
EVT_LOGOUT          = 'LO'    # logout (manual or timeout)
EVT_PW_CHANGE_OK    = 'SPC'   # successful password change
EVT_PW_CHANGE_FAIL  = 'FPC'   # failed password change
EVT_PW_RESET        = 'RPW'   # admin password reset
EVT_REAUTH_OK       = 'RA'    # re-authentication success
EVT_REAUTH_FAIL     = 'RAF'   # re-authentication failure
EVT_USER_ADD        = 'AU'    # user account created
EVT_USER_DEL        = 'DU'    # user account deleted
EVT_LIST_USERS      = 'LSU'   # user list viewed
EVT_RECORD_ADD      = 'ADR'   # record added
EVT_RECORD_DEL      = 'DER'   # record deleted
EVT_RECORD_EDIT     = 'EDR'   # record edited
EVT_RECORD_GET      = 'RER'   # record retrieved
EVT_IMPORT          = 'IMD'   # database import
EVT_EXPORT          = 'EXD'   # database export
EVT_PRIV_VIOLATION  = 'PV'    # privilege violation
EVT_INJECTION       = 'INJ'   # injection pattern detected
EVT_SESSION_TIMEOUT = 'ST'    # session timed out


def audit_log(event_type: str, user_id: str, detail: str = ''):
    """Append one event record. Thread-safe at process level (single-process app)."""
    records = _read_log()
    now = datetime.now()
    records.append({
        'Date':   now.strftime('%Y-%m-%d'),
        'Time':   now.strftime('%H:%M:%S'),
        'Type':   event_type,
        'UserID': user_id or '',
        'Detail': detail or '',
    })
    # FIFO eviction
    if len(records) > MAX_RECORDS:
        records = records[-MAX_RECORDS:]
    _write_log(records)


def audit_query(user_id_filter: str = None):
    """Return list of event dicts, optionally filtered by UserID."""
    records = _read_log()
    if user_id_filter:
        records = [r for r in records if r.get('UserID') == user_id_filter]
    return records


# ── Internal I/O ──────────────────────────────────────────────────────────────

_FIELDS = ['Date', 'Time', 'Type', 'UserID', 'Detail']


def _read_log():
    if not os.path.exists(AUDIT_FILE):
        return []
    try:
        with open(AUDIT_FILE, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception:
        return []


def _write_log(records: list):
    with open(AUDIT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDS, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)
    os.chmod(AUDIT_FILE, stat.S_IRUSR | stat.S_IWUSR)