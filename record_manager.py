"""
record_manager.py — Record Manager Module
Secret: record schema, field validation/injection rules, semicolon-CSV import format,
        how records are keyed per user, and AES-256 export encryption.
Callers pass field dicts and receive result codes; they never touch raw storage.
"""

import csv
import io
import os
import re
import stat

import crypto
import storage
import audit_logger as al

MAX_RECORDS     = 256          # per user (SRS limits)
MAX_FIELD_LEN   = 64           # chars (SRS limits)
MAX_IMPORT_SIZE = 10 * 1024 * 1024  # 10 MB (REQ-IMD)

REQUIRED_FIELDS = ('name', 'address', 'phone')
VALID_FIELDS    = frozenset(REQUIRED_FIELDS)
_RECORDID_RE    = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

# Shell metacharacters and SQL injection fragments to reject (SR-7, SEC-4)
_SHELL_PATTERN = re.compile(r'[;&|`$<>()\\\n\r]')
_SQL_PATTERN   = re.compile(
    r"('|\"|--|\bOR\b|\bAND\b|\bDROP\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|"
    r"\bUNION\b|\bEXEC\b|\bSCRIPT\b)",
    re.IGNORECASE
)

# ── Result codes ──────────────────────────────────────────────────────────────
REC_OK              = 0
REC_NO_SESSION      = 1
REC_UNAUTHORIZED    = 2   # admin trying to access records
REC_NO_FILE         = 3
REC_FILE_TOO_LARGE  = 4
REC_PATH_TRAVERSAL  = 5
REC_CANNOT_OPEN     = 6
REC_INVALID_FORMAT  = 7
REC_DUPLICATE       = 7   # same slot — context distinguishes
REC_MAX_RECORDS     = 8
REC_INVALID_FIELDS  = 5   # context distinguishes from path traversal
REC_INJECTION       = 6
REC_NOT_FOUND       = 5
REC_WRITE_ERROR     = 6
REC_NO_RECORDS      = 7
REC_ERROR           = 99


def _load_db():
    db, _ = storage.storage_read_db()
    return db

def _save_db(db):
    storage.storage_write_db(db)


# ── Input validation helpers ──────────────────────────────────────────────────

def _is_safe(value: str) -> bool:
    """Return True only if value passes all injection and length checks."""
    if not isinstance(value, str) or len(value) > MAX_FIELD_LEN:
        return False
    if _SHELL_PATTERN.search(value):
        return False
    if _SQL_PATTERN.search(value):
        return False
    return True


def _validate_path(filepath: str) -> bool:
    """Reject path traversal sequences and absolute paths (SEC-9)."""
    danger = ['../', '..' + os.sep, '~/', '~' + os.sep]
    for d in danger:
        if d in filepath:
            return False
    if os.path.isabs(filepath):
        return False
    return True


def _validate_fields(fields: dict) -> tuple[bool, bool]:
    """Returns (fields_ok, injection_detected)."""
    for k, v in fields.items():
        if k not in VALID_FIELDS:
            return False, False
        if not _is_safe(v):
            return False, True
    return True, False


# ── Public interface ──────────────────────────────────────────────────────────

def records_add(user_id: str, record_id: str, fields: dict) -> int:
    if not _RECORDID_RE.match(record_id):
        return 4   # invalid recordID

    db = _load_db()
    user_recs = db['records'].get(user_id, {})

    if record_id in user_recs:
        return 7   # duplicate

    if len(user_recs) >= MAX_RECORDS:
        return 8   # max reached

    # Check required fields are present and non-empty
    for req in REQUIRED_FIELDS:
        if not fields.get(req, '').strip():
            return 5   # missing/invalid field

    ok, injected = _validate_fields(fields)
    if not ok:
        if injected:
            al.audit_log(al.EVT_INJECTION, user_id, f'ADR {record_id}')
            return 6
        return 5

    user_recs[record_id] = {k: fields[k].strip() for k in REQUIRED_FIELDS}
    db['records'][user_id] = user_recs
    _save_db(db)
    al.audit_log(al.EVT_RECORD_ADD, user_id, record_id)
    return 0


def records_delete(user_id: str, record_id: str) -> int:
    db = _load_db()
    user_recs = db['records'].get(user_id, {})

    if record_id not in user_recs:
        return 5   # not found

    del user_recs[record_id]
    db['records'][user_id] = user_recs
    _save_db(db)
    al.audit_log(al.EVT_RECORD_DEL, user_id, record_id)
    return 0


def records_edit(user_id: str, record_id: str, fields: dict) -> int:
    if not fields:
        return 5   # nothing to update

    db = _load_db()
    user_recs = db['records'].get(user_id, {})

    if record_id not in user_recs:
        return 5   # not found

    ok, injected = _validate_fields(fields)
    if not ok:
        if injected:
            al.audit_log(al.EVT_INJECTION, user_id, f'EDR {record_id}')
            return 6
        return 5

    user_recs[record_id].update({k: v.strip() for k, v in fields.items() if k in VALID_FIELDS})
    db['records'][user_id] = user_recs
    _save_db(db)
    al.audit_log(al.EVT_RECORD_EDIT, user_id, record_id)
    return 0


def records_get(user_id: str, record_id: str = None,
                fieldnames: list = None) -> tuple[dict | None, int]:
    db = _load_db()
    user_recs = db['records'].get(user_id, {})

    if record_id:
        if record_id not in user_recs:
            return None, 5   # not found
        result = {record_id: user_recs[record_id]}
    else:
        result = dict(user_recs)

    # Filter to requested fieldnames
    if fieldnames:
        for fn in fieldnames:
            if fn not in VALID_FIELDS:
                return None, 4   # invalid fieldname
        result = {
            rid: {k: v for k, v in rec.items() if k in fieldnames}
            for rid, rec in result.items()
        }

    al.audit_log(al.EVT_RECORD_GET, user_id, record_id or 'all')
    return result, 0


def records_import(user_id: str, filepath: str) -> tuple[dict | None, int]:
    if not _validate_path(filepath):
        al.audit_log(al.EVT_PRIV_VIOLATION, user_id, f'path traversal IMD {filepath}')
        return None, 5

    if not os.path.exists(filepath):
        return None, 6   # cannot open

    if os.path.getsize(filepath) > MAX_IMPORT_SIZE:
        return None, 4   # too large

    db = _load_db()
    user_recs = db['records'].get(user_id, {})

    total = imported = skipped = 0
    error_lines = []

    try:
        with open(filepath, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')
            if not reader.fieldnames or 'recordID' not in reader.fieldnames:
                return None, 7   # invalid CSV — missing header

            for line_num, row in enumerate(reader, start=2):
                total += 1
                rid = row.get('recordID', '').strip()

                # Validate recordID
                if not rid or not _RECORDID_RE.match(rid):
                    skipped += 1
                    error_lines.append(f"Line {line_num}: invalid or missing recordID")
                    continue

                if rid in user_recs:
                    skipped += 1
                    error_lines.append(f"Line {line_num}: duplicate recordID '{rid}'")
                    continue

                if len(user_recs) >= MAX_RECORDS:
                    skipped += 1
                    error_lines.append(f"Line {line_num}: max records reached, stopping")
                    break

                # Validate and sanitize fields
                fields = {}
                safe = True
                for req in REQUIRED_FIELDS:
                    val = row.get(req, '').strip()
                    if not val:
                        error_lines.append(f"Line {line_num}: missing field '{req}'")
                        safe = False
                        break
                    if not _is_safe(val):
                        al.audit_log(al.EVT_INJECTION, user_id, f'IMD line {line_num} field {req}')
                        error_lines.append(f"Line {line_num}: injection pattern in '{req}'")
                        safe = False
                        break
                    fields[req] = val

                if not safe:
                    skipped += 1
                    continue

                user_recs[rid] = fields
                imported += 1

    except Exception as e:
        return None, 7   # malformed CSV

    db['records'][user_id] = user_recs
    _save_db(db)
    al.audit_log(al.EVT_IMPORT, user_id, f'{imported} imported, {skipped} skipped')

    return {'total': total, 'imported': imported,
            'skipped': skipped, 'errors': error_lines}, 0


def records_export(user_id: str, filepath: str) -> int:
    if not _validate_path(filepath):
        al.audit_log(al.EVT_PRIV_VIOLATION, user_id, f'path traversal EXD {filepath}')
        return 4

    db = _load_db()
    user_recs = db['records'].get(user_id, {})

    if not user_recs:
        return 7   # no records to export

    try:
        # Build CSV in memory, then encrypt before writing (SR-8: no plaintext temp files)
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=['recordID'] + list(REQUIRED_FIELDS),
            delimiter=';', extrasaction='ignore'
        )
        writer.writeheader()
        for rid, rec in user_recs.items():
            writer.writerow({'recordID': rid, **rec})

        plaintext = buf.getvalue().encode('utf-8')
        ciphertext, code = crypto.crypto_encrypt(plaintext, storage.DB_KEY_ID)
        if code != crypto.CRYPTO_OK:
            return 6

        with open(filepath, 'wb') as f:
            f.write(ciphertext)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)   # 600 (REQ-EXD)

        al.audit_log(al.EVT_EXPORT, user_id,
                     f'file={filepath} records={len(user_recs)}')
        return 0

    except PermissionError:
        return 6
    except Exception:
        return 6