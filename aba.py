"""
aba.py — CLI Parser & Main Entry Point
Secret: exact command syntax, tokenization rules, argument ordering.
Dispatches structured calls to modules; contains no business logic itself.
"""

import getpass
import sys

import storage
import auth
import access_control as acl
import user_manager as um
import record_manager as rm
import audit_logger as al

VERSION = "1.0"

# ── Startup ───────────────────────────────────────────────────────────────────

def _init():
    """Bootstrap encryption key and database on first run."""
    storage.storage_init_key()
    db, code = storage.storage_read_db()
    if code == storage.STORE_NOT_FOUND:
        _seed_db()
    elif code != storage.STORE_OK:
        _die("Database is corrupted or unreadable. Check file permissions.")


def _seed_db():
    """Create the initial database with only the admin account."""
    db = {
        'users': {
            'admin': {
                'password_hash':  None,   # no password — first login sets it
                'role':           'admin',
                'force_change':   True,
                'failed_attempts': 0,
                'locked':         False,
            }
        },
        'records': {}
    }
    code = storage.storage_write_db(db)
    if code != storage.STORE_OK:
        _die("Cannot write initial database.")


def _die(msg: str):
    print(f"FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _check_auth(cmd: str) -> bool:
    """
    Enforce session existence and timeout before a command that needs auth.
    Prints the appropriate SRS-specified message and returns False on failure.
    """
    if not auth.auth_is_authenticated():
        print("No active login session")
        al.audit_log(al.EVT_PRIV_VIOLATION, '', f'unauthenticated {cmd}')
        return False
    result = auth.auth_check_session_timeout()
    if result == auth.AUTH_EXPIRED:
        print("Session expired. Please log in again.")
        return False
    return True


def _check_admin(cmd: str) -> bool:
    """Additional check that the current session is an admin."""
    if not auth.auth_is_admin():
        print("Admin not authorized")
        al.audit_log(al.EVT_PRIV_VIOLATION, auth.auth_get_active_user(),
                     f'non-admin attempted {cmd}')
        return False
    return True


def _check_not_admin(cmd: str) -> bool:
    """Ensure the current session is NOT admin (admin cannot manage records per BR-2)."""
    if auth.auth_is_admin():
        print("Admin not authorized")
        al.audit_log(al.EVT_PRIV_VIOLATION, 'admin', f'admin attempted record op {cmd}')
        return False
    return True


def _do_reauth() -> bool:
    """Prompt for password re-entry (SR-6). Returns True on success."""
    password = getpass.getpass("Re-enter your password to confirm: ")
    result = auth.auth_verify_password(password)
    if result == auth.AUTH_OK:
        return True
    print("Invalid credentials")
    return False


def _parse_fields(tokens: list[str]) -> dict:
    """Parse 'field=value' tokens into a dict."""
    fields = {}
    for token in tokens:
        if '=' in token:
            k, _, v = token.partition('=')
            fields[k.strip().lower()] = v.strip()
    return fields


def _pw_error(code: int):
    messages = {
        auth.AUTH_INVALID_CREDENTIALS: "Invalid credentials",
        auth.AUTH_PASSWORDS_NO_MATCH:  "Passwords do not match",
        auth.AUTH_ILLEGAL_CHARS:       "Illegal characters in password",
        auth.AUTH_WEAK_PASSWORD:       "Password does not meet complexity requirements",
    }
    print(messages.get(code, "Password error"))


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_lin(args: list[str]):
    if len(args) < 1:
        print("Usage: LIN <userID>")
        return
    user_id = args[0]

    # Password prompt — hidden input (security: not echoed to terminal)
    password = getpass.getpass("Password: ")
    result = auth.auth_login(user_id, password)

    if result == auth.AUTH_OK:
        print("OK")

    elif result == auth.AUTH_FIRST_LOGIN:
        # First login or admin-forced password reset
        print("You must set a new password before continuing.")
        new_pw  = getpass.getpass("New password: ")
        confirm = getpass.getpass("Confirm new password: ")
        change  = auth.auth_change_password('', new_pw, confirm, skip_old_check=True)
        if change == auth.AUTH_OK:
            al.audit_log(al.EVT_LOGIN_FIRST, user_id, 'password set')
            print("OK")
        else:
            _pw_error(change)
            auth.auth_logout()   # clear the partial session

    elif result == auth.AUTH_INVALID_CREDENTIALS:
        print("Invalid credentials")
    elif result == auth.AUTH_ACCOUNT_LOCKED:
        print("Account locked")
    elif result == auth.AUTH_ALREADY_LOGGED_IN:
        print("Already logged in. Use LOU to logout first.")
    else:
        print("Invalid credentials")


def cmd_lou(args: list[str]):
    if not auth.auth_is_authenticated():
        print("No active login session")
        return
    auth.auth_logout()
    print("OK")


def cmd_chp(args: list[str]):
    if not _check_auth('CHP'):
        return
    if len(args) < 1:
        print("Usage: CHP <old_password>")
        return
    old_pw  = args[0]
    new_pw  = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")
    result  = auth.auth_change_password(old_pw, new_pw, confirm)
    if result == auth.AUTH_OK:
        print("OK")
    else:
        _pw_error(result)


def cmd_adu(args: list[str]):
    if not _check_auth('ADU') or not _check_admin('ADU'):
        return
    if len(args) < 1:
        print("Usage: ADU <userID>")
        return
    if not _do_reauth():
        return
    result = um.users_add(auth.auth_get_active_user(), args[0])
    if   result == um.USR_OK:             print("OK")
    elif result == um.USR_INVALID_FORMAT: print("Invalid userID format (alphanumeric, max 16 chars)")
    elif result == um.USR_EXISTS:         print("Account already exists")
    elif result == um.USR_MAX_USERS:      print("Number of records exceeds maximum")
    else:                                 print("Error creating user")


def cmd_deu(args: list[str]):
    if not _check_auth('DEU') or not _check_admin('DEU'):
        return
    if len(args) < 1:
        print("Usage: DEU <userID>")
        return
    if not _do_reauth():
        return
    result = um.users_delete(auth.auth_get_active_user(), args[0])
    if   result == um.USR_OK:                    print("OK")
    elif result == um.USR_INVALID_FORMAT:         print("Invalid userID format")
    elif result == um.USR_NOT_FOUND:              print("Account does not exist")
    elif result == um.USR_CANNOT_DEL_SELF:        print("Cannot delete your own account")
    elif result == um.USR_CANNOT_DEL_LAST_ADMIN:  print("Cannot delete the last admin account")
    else:                                         print("Error deleting user")


def cmd_lsu(args: list[str]):
    if not _check_auth('LSU') or not _check_admin('LSU'):
        return
    if not _do_reauth():
        return
    users, _ = um.users_list(auth.auth_get_active_user())
    if users:
        for u in users:
            print(u)
    else:
        print("(no regular users)")
    print("OK")


def cmd_rpw(args: list[str]):
    if not _check_auth('RPW') or not _check_admin('RPW'):
        return
    if len(args) < 1:
        print("Usage: RPW <userID>")
        return
    if not _do_reauth():
        return
    target = args[0]
    new_pw  = getpass.getpass(f"New password for {target}: ")
    result  = um.users_reset_password(auth.auth_get_active_user(), target, new_pw)
    if   result == um.USR_OK:               print("OK")
    elif result == um.USR_NOT_FOUND:        print("Account does not exist")
    elif result == um.USR_WEAK_PASSWORD:    print("Password does not meet complexity requirements")
    elif result == um.USR_CANNOT_RESET_SELF: print("Use CHP to change your own password")
    else:                                   print("Error resetting password")


def cmd_dal(args: list[str]):
    if not _check_auth('DAL') or not _check_admin('DAL'):
        return
    user_filter = args[0] if args else None
    records = al.audit_query(user_filter)
    if not records:
        print("No audit records found")
    else:
        header = f"{'Date':<12} {'Time':<10} {'Type':<6} {'UserID':<18} Detail"
        print(header)
        print('-' * len(header))
        for r in records:
            print(f"{r.get('Date',''):<12} {r.get('Time',''):<10} "
                  f"{r.get('Type',''):<6} {r.get('UserID',''):<18} {r.get('Detail','')}")
    print("OK")


def cmd_adr(args: list[str]):
    if not _check_auth('ADR') or not _check_not_admin('ADR'):
        return
    if len(args) < 1:
        print("Usage: ADR <recordID> [name=value address=value phone=value]")
        return
    record_id = args[0]
    fields    = _parse_fields(args[1:])

    # Prompt interactively for any missing required fields
    for req in ('name', 'address', 'phone'):
        if req not in fields:
            fields[req] = input(f"  {req.capitalize()}: ")

    result = rm.records_add(auth.auth_get_active_user(), record_id, fields)
    if   result == 0: print("OK")
    elif result == 4: print("Invalid recordID")
    elif result == 5: print("Invalid or missing fields")
    elif result == 6: print("Invalid input detected")
    elif result == 7: print("Duplicate recordID")
    elif result == 8: print("Number of records exceeds maximum")
    else:             print("Error adding record")


def cmd_der(args: list[str]):
    if not _check_auth('DER') or not _check_not_admin('DER'):
        return
    if len(args) < 1:
        print("Usage: DER <recordID>")
        return
    result = rm.records_delete(auth.auth_get_active_user(), args[0])
    if   result == 0: print("OK")
    elif result == 5: print("RecordID not found")
    else:             print("Error deleting record")


def cmd_edr(args: list[str]):
    if not _check_auth('EDR') or not _check_not_admin('EDR'):
        return
    if len(args) < 2:
        print("Usage: EDR <recordID> <field=value> [...]")
        return
    record_id = args[0]
    fields    = _parse_fields(args[1:])
    if not fields:
        print("No valid field=value pairs provided")
        return
    result = rm.records_edit(auth.auth_get_active_user(), record_id, fields)
    if   result == 0: print("OK")
    elif result == 5: print("RecordID not found")
    elif result == 6: print("Invalid input detected")
    else:             print("Error editing record")


def cmd_rer(args: list[str]):
    if not _check_auth('RER') or not _check_not_admin('RER'):
        return

    record_id  = None
    fieldnames = []

    # First arg without '=' is treated as a recordID
    if args and '=' not in args[0]:
        record_id  = args[0]
        fieldnames = args[1:]
    else:
        fieldnames = args

    records, code = rm.records_get(auth.auth_get_active_user(), record_id,
                                   fieldnames if fieldnames else None)
    if code == 5:
        print("RecordID not found")
        return
    if code == 4:
        print("Invalid fieldname")
        return

    if not records:
        print("No records found")
    else:
        for rid, rec in records.items():
            print(f"RecordID: {rid}")
            for k, v in rec.items():
                print(f"  {k}: {v}")
    print("OK")


def cmd_imd(args: list[str]):
    if not _check_auth('IMD') or not _check_not_admin('IMD'):
        return
    if len(args) < 1:
        print("Usage: IMD <input_file>")
        return
    stats, code = rm.records_import(auth.auth_get_active_user(), args[0])
    if   code == 4: print("File exceeds 10 MB limit")
    elif code == 5: print("Path traversal attempt detected")
    elif code == 6: print("Cannot open file")
    elif code == 7: print("Invalid CSV format (expected semicolon-delimited with recordID,name,address,phone headers)")
    elif code == 0:
        print(f"Import complete: {stats['total']} lines, "
              f"{stats['imported']} imported, {stats['skipped']} skipped")
        for err in stats['errors']:
            print(f"  Skipped: {err}")
        print("OK")
    else:
        print("Import error")


def cmd_exd(args: list[str]):
    if not _check_auth('EXD') or not _check_not_admin('EXD'):
        return
    if len(args) < 1:
        print("Usage: EXD <output_file>")
        return
    result = rm.records_export(auth.auth_get_active_user(), args[0])
    if   result == 0: print("OK")
    elif result == 4: print("Path traversal attempt detected")
    elif result == 7: print("No records to export")
    elif result == 6: print("Write error")
    else:             print("Export error")


def cmd_hlp(args: list[str]):
    all_cmds = {
        'LIN': 'LIN <userID>                        — Login',
        'LOU': 'LOU                                 — Logout',
        'CHP': 'CHP <old_password>                  — Change password',
        'ADU': 'ADU <userID>                        — Add user (admin)',
        'DEU': 'DEU <userID>                        — Delete user (admin)',
        'LSU': 'LSU                                 — List users (admin)',
        'RPW': 'RPW <userID>                        — Reset user password (admin)',
        'DAL': 'DAL [<userID>]                      — Display audit log (admin)',
        'ADR': 'ADR <recordID> [field=value ...]    — Add address record',
        'DER': 'DER <recordID>                      — Delete address record',
        'EDR': 'EDR <recordID> <field=value> [...]  — Edit address record',
        'RER': 'RER [<recordID>] [<fieldname> ...]  — Read address record(s)',
        'IMD': 'IMD <input_file>                    — Import database from CSV',
        'EXD': 'EXD <output_file>                   — Export database to encrypted CSV',
        'HLP': 'HLP [<command>]                     — Show help',
        'EXT': 'EXT                                 — Exit',
    }

    # If authenticated, filter commands by role
    active_role = acl.acl_get_role(auth.auth_get_active_user())

    if args:
        cmd_name = args[0].upper()
        if cmd_name in all_cmds:
            print(all_cmds[cmd_name])
        else:
            print("Error: Unknown command. Use HLP to see available commands.")
        return

    for cmd_name, line in all_cmds.items():
        # Show role-appropriate commands; always show universal ones
        if active_role == 'admin' and not acl.acl_can_perform('admin', cmd_name):
            continue
        if active_role == 'user' and not acl.acl_can_perform('user', cmd_name):
            continue
        print(line)


# ── Command dispatch table ────────────────────────────────────────────────────

_DISPATCH = {
    'LIN': cmd_lin,
    'LOU': cmd_lou,
    'CHP': cmd_chp,
    'ADU': cmd_adu,
    'DEU': cmd_deu,
    'LSU': cmd_lsu,
    'RPW': cmd_rpw,
    'DAL': cmd_dal,
    'ADR': cmd_adr,
    'DER': cmd_der,
    'EDR': cmd_edr,
    'RER': cmd_rer,
    'IMD': cmd_imd,
    'EXD': cmd_exd,
    'HLP': cmd_hlp,
}


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    _init()
    print(f'Address Book Application, version {VERSION}. Type "HLP" for commands.')

    while True:
        try:
            raw = input("ABA> ").strip()
        except (EOFError, KeyboardInterrupt):
            # Graceful exit on Ctrl-D / Ctrl-C
            print()
            if auth.auth_is_authenticated():
                auth.auth_logout()
            break

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].upper()
        args  = parts[1:]

        if cmd == 'EXT':
            if auth.auth_is_authenticated():
                auth.auth_logout()
            break

        if cmd not in _DISPATCH:
            print("Unrecognized command")
            continue

        _DISPATCH[cmd](args)


if __name__ == '__main__':
    main()