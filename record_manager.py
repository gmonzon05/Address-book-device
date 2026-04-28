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
import access_control as acl

MAX_RECORDS     = 256
MAX_FIELD_LEN   = 64
MAX_IMPORT_SIZE = 10 * 1024 * 1024

REQUIRED_FIELDS = ('name', 'address', 'phone')
VALID_FIELDS    = frozenset(REQUIRED_FIELDS)
_RECORDID_RE    = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

_SHELL_PATTERN = re.compile(r'[;&|`$<>()\\\n\r]')
_SQL_PATTERN   = re.compile(
    r"('|\"|--|\bOR\b|\bAND\b|\bDROP\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|"
    r"\bUNION\b|\bEXEC\b|\bSCRIPT\b)",
    re.IGNORECASE
)

REC_UNAUTHORIZED = 2


def _load_db():
    db, _ = storage.storage_read_db()
    return db

def _save_db(db):
    storage.storage_write_db(db)

def _is_safe(value: str) -> bool:
    if _SHELL_PATTERN.search(value):
        return False
    if _SQL_PATTERN.search(value):
        return False
    return True

def _validate_path(filepath: str) -> bool:
    for danger in ['../', '..' + os.sep, '~/', '~' + os.sep]:
        if danger in filepath:
            return False
    return not os.path.isabs(filepath)

def _validate_fields(fields: dict) -> tuple:
    for k, v in fields.items():
        if k not in VALID_FIELDS:
            return False, False
        if not isinstance(v, str) or len(v) > MAX_FIELD_LEN:
            return False, False
        if not _is_safe(v):
            return False, True
    return True, False

def _is_admin(user_id: str) -> bool:
    return not acl.acl_can_perform(acl.acl_get_role(user_id), 'ADR')


def records_add(user_id: str, record_id: str, fields: dict) -> int:
    if _is_admin(user_id):
        return REC_UNAUTHORIZED
    if not _RECORDID_RE.match(record_id):
        return 4
    db = _load_db()
    user_recs = db['records'].get(user_id, {})
    if record_id in user_recs:
        return 7
    if len(user_recs) >= MAX_RECORDS:
        return 8
    for req in REQUIRED_FIELDS:
        if not fields.get(req, '').strip():
            return 5
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
    if _is_admin(user_id):
        return REC_UNAUTHORIZED
    db = _load_db()
    user_recs = db['records'].get(user_id, {})
    if record_id not in user_recs:
        return 5
    del user_recs[record_id]
    db['records'][user_id] = user_recs
    _save_db(db)
    al.audit_log(al.EVT_RECORD_DEL, user_id, record_id)
    return 0


def records_edit(user_id: str, record_id: str, fields: dict) -> int:
    if _is_admin(user_id):
        return REC_UNAUTHORIZED
    if not fields:
        return 5
    db = _load_db()
    user_recs = db['records'].get(user_id, {})
    if record_id not in user_recs:
        return 5
    ok, injected = _validate_fields(fields)
    if not ok:
        if injected:
            al.audit_log(al.EVT_INJECTION, user_id, f'EDR {record_id}')
            return 6
        return 5
    user_recs[record_id].update(
        {k: v.strip() for k, v in fields.items() if k in VALID_FIELDS}
    )
    db['records'][user_id] = user_recs
    _save_db(db)
    al.audit_log(al.EVT_RECORD_EDIT, user_id, record_id)
    return 0


def records_get(user_id: str, record_id: str = None, fieldnames: list = None):
    if _is_admin(user_id):
        return None, REC_UNAUTHORIZED
    db = _load_db()
    user_recs = db['records'].get(user_id, {})
    if record_id:
        if record_id not in user_recs:
            return None, 5
        result = {record_id: user_recs[record_id]}
    else:
        result = dict(user_recs)
    if fieldnames:
        for fn in fieldnames:
            if fn not in VALID_FIELDS:
                return None, 4
        result = {rid: {k: v for k, v in rec.items() if k in fieldnames}
                  for rid, rec in result.items()}
    al.audit_log(al.EVT_RECORD_GET, user_id, record_id or 'all')
    return result, 0


def records_import(user_id: str, filepath: str):
    if _is_admin(user_id):
        return None, REC_UNAUTHORIZED
    if not _validate_path(filepath):
        al.audit_log(al.EVT_PRIV_VIOLATION, user_id, f'path traversal IMD {filepath}')
        return None, 5
    if not os.path.exists(filepath):
        return None, 6
    if os.path.getsize(filepath) > MAX_IMPORT_SIZE:
        return None, 4
    db = _load_db()
    user_recs = db['records'].get(user_id, {})
    total = imported = skipped = 0
    error_lines = []
    try:
        with open(filepath, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')
            if not reader.fieldnames or 'recordID' not in reader.fieldnames:
                return None, 7
            for line_num, row in enumerate(reader, start=2):
                total += 1
                rid = row.get('recordID', '').strip()
                if not rid or not _RECORDID_RE.match(rid):
                    skipped += 1
                    error_lines.append(f"Line {line_num}: invalid recordID")
                    continue
                if rid in user_recs:
                    skipped += 1
                    error_lines.append(f"Line {line_num}: duplicate '{rid}'")
                    continue
                if len(user_recs) >= MAX_RECORDS:
                    skipped += 1
                    error_lines.append(f"Line {line_num}: max records reached")
                    break
                fields = {}
                safe = True
                for req in REQUIRED_FIELDS:
                    val = row.get(req, '').strip()
                    if not val:
                        error_lines.append(f"Line {line_num}: missing '{req}'")
                        safe = False
                        break
                    if len(val) > MAX_FIELD_LEN or not _is_safe(val):
                        al.audit_log(al.EVT_INJECTION, user_id, f'IMD line {line_num}')
                        error_lines.append(f"Line {line_num}: injection in '{req}'")
                        safe = False
                        break
                    fields[req] = val
                if not safe:
                    skipped += 1
                    continue
                user_recs[rid] = fields
                imported += 1
    except Exception:
        return None, 7
    db['records'][user_id] = user_recs
    _save_db(db)
    al.audit_log(al.EVT_IMPORT, user_id, f'{imported} imported, {skipped} skipped')
    return {'total': total, 'imported': imported,
            'skipped': skipped, 'errors': error_lines}, 0


def records_export(user_id: str, filepath: str) -> int:
    if _is_admin(user_id):
        return REC_UNAUTHORIZED
    if not _validate_path(filepath):
        al.audit_log(al.EVT_PRIV_VIOLATION, user_id, f'path traversal EXD {filepath}')
        return 4
    db = _load_db()
    user_recs = db['records'].get(user_id, {})
    if not user_recs:
        return 7
    try:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=['recordID'] + list(REQUIRED_FIELDS),
                                delimiter=';', extrasaction='ignore')
        writer.writeheader()
        for rid, rec in user_recs.items():
            writer.writerow({'recordID': rid, **rec})
        plaintext = buf.getvalue().encode('utf-8')
        ciphertext, code = crypto.crypto_encrypt(plaintext, storage.DB_KEY_ID)
        if code != crypto.CRYPTO_OK:
            return 6
        with open(filepath, 'wb') as f:
            f.write(ciphertext)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
        al.audit_log(al.EVT_EXPORT, user_id, f'file={filepath} records={len(user_recs)}')
        return 0
    except PermissionError:
        return 6
    except Exception:
        return 6