#!/usr/bin/env python3
"""
fuzz_check.py — ABA Fuzz Results Checker
Reads ABA stdout from stdin, compares each response to the manifest,
and produces a detailed pass/fail report.

Usage (pipeline):
    python3 fuzz_gen.py | python3 aba.py --fuzz | python3 fuzz_check.py > results.txt

Usage (file-based):
    python3 fuzz_check.py --aba-output aba_out.txt
"""

import json
import sys
import re
import collections

MANIFEST_FILE = "fuzz_manifest.jsonl"

# ── Load manifest ─────────────────────────────────────────────────────────────

manifest = []
try:
    with open(MANIFEST_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                manifest.append(json.loads(line))
except FileNotFoundError:
    print(f"ERROR: {MANIFEST_FILE} not found. Run fuzz_gen.py first.", file=sys.stderr)
    sys.exit(1)

print(f"Loaded {len(manifest)} manifest entries.", file=sys.stderr)

# ── Parse ABA output ──────────────────────────────────────────────────────────

if "--aba-output" in sys.argv:
    idx = sys.argv.index("--aba-output")
    aba_input = open(sys.argv[idx + 1], encoding="utf-8")
else:
    aba_input = sys.stdin

responses = {}        # seq_number -> response_text
current_seq  = None
current_lines = []
startup_skipped = False

for raw_line in aba_input:
    line = raw_line.rstrip("\n")

    # Skip the startup banner
    if not startup_skipped and "Address Book Application" in line:
        startup_skipped = True
        continue

    if line.startswith("__FUZZ_START_"):
        try:
            current_seq   = int(line.split("__FUZZ_START_")[1].rstrip("__").strip("_"))
            current_lines = []
        except ValueError:
            pass
        continue

    if line.startswith("__FUZZ_END_"):
        if current_seq is not None:
            responses[current_seq] = "\n".join(current_lines).strip()
        current_seq   = None
        current_lines = []
        continue

    if current_seq is not None:
        current_lines.append(line)

print(f"Parsed {len(responses)} ABA responses.", file=sys.stderr)

# ── Evaluate checks ───────────────────────────────────────────────────────────

PASS = "PASS"
FAIL = "FAIL"
MISS = "MISS"   # no response found for this seq

results       = []
by_category   = collections.defaultdict(lambda: {"pass": 0, "fail": 0, "miss": 0})
crash_detected = []
security_findings = []

def evaluate(entry, response):
    """Apply all checks from the manifest entry to the actual response."""
    failures = []
    for chk in entry["checks"]:
        t = chk["type"]
        v = chk["value"]
        if t == "contains":
            ok = v in response
        elif t == "not_contains":
            ok = v not in response
        elif t == "exact":
            ok = response.strip() == v
        else:
            ok = True    # unknown check type — pass

        if not ok:
            failures.append(f"[{t}] expected '{v[:60]}' — got: '{response[:80]}'")

    return failures


for entry in manifest:
    seq      = entry["seq"]
    category = entry["category"]
    cmd      = entry["cmd"]
    desc     = entry["desc"]
    response = responses.get(seq)

    if response is None:
        status = MISS
        failures = ["No ABA response captured for this sequence number"]
        by_category[category]["miss"] += 1
    else:
        failures = evaluate(entry, response)
        if failures:
            status = FAIL
            by_category[category]["fail"] += 1
        else:
            status = PASS
            by_category[category]["pass"] += 1

    # Special flagging
    if response and "Traceback" in response:
        crash_detected.append((seq, cmd, response))
    if status == FAIL:
        # Is this a security-relevant failure?
        sec_categories = {"inj_", "auth_", "unauth", "role_", "file_path",
                          "admin_record", "admin_dal_inj"}
        if any(category.startswith(s) for s in sec_categories):
            security_findings.append((seq, status, category, cmd, response, failures))

    results.append({
        "seq":      seq,
        "status":   status,
        "category": category,
        "desc":     desc,
        "cmd":      cmd,
        "response": response or "(no response)",
        "failures": failures,
    })

# ── Report ────────────────────────────────────────────────────────────────────

total  = len(results)
passed = sum(1 for r in results if r["status"] == PASS)
failed = sum(1 for r in results if r["status"] == FAIL)
missed = sum(1 for r in results if r["status"] == MISS)

SEP = "=" * 78

print(SEP)
print("  ABA FUZZ TEST REPORT")
print(SEP)
print(f"  Total test cases : {total}")
print(f"  PASS             : {passed}  ({100*passed//max(total,1)}%)")
print(f"  FAIL             : {failed}")
print(f"  MISS (no resp)   : {missed}")
print(f"  Crashes detected : {len(crash_detected)}")
print(f"  Security findings: {len(security_findings)}")
print()

# Per-category summary
print(f"{'Category':<35} {'Pass':>6} {'Fail':>6} {'Miss':>6}")
print("-" * 55)
for cat in sorted(by_category):
    d = by_category[cat]
    print(f"  {cat:<33} {d['pass']:>6} {d['fail']:>6} {d['miss']:>6}")
print()

# Crash report (highest priority)
if crash_detected:
    print(SEP)
    print("  *** CRASH / TRACEBACK DETECTED (CRITICAL) ***")
    print(SEP)
    for seq, cmd, resp in crash_detected:
        print(f"  seq={seq}  cmd={cmd[:60]}")
        print(f"  response:\n{resp[:500]}")
        print()
else:
    print("  [OK] No crashes or Python tracebacks detected.")
print()

# Security-relevant failures
if security_findings:
    print(SEP)
    print("  *** SECURITY-RELEVANT FAILURES ***")
    print(SEP)
    for seq, status, cat, cmd, resp, failures in security_findings:
        print(f"  seq={seq}  category={cat}")
        print(f"  cmd     : {cmd[:80]}")
        print(f"  response: {resp[:80]}")
        for f in failures:
            print(f"  ✗ {f}")
        print()
else:
    print("  [OK] No security-relevant failures detected.")
print()

# All failures (detailed)
all_fails = [r for r in results if r["status"] != PASS]
if all_fails:
    print(SEP)
    print(f"  FAILED / MISSED TESTS ({len(all_fails)} total)")
    print(SEP)
    for r in all_fails:
        print(f"  [{r['status']}] seq={r['seq']}  {r['category']}  {r['desc'][:50]}")
        print(f"        cmd     : {r['cmd'][:80]}")
        print(f"        response: {r['response'][:80]}")
        for f in r["failures"]:
            print(f"        ✗ {f}")
        print()

# Final verdict
print(SEP)
if crashed := len(crash_detected):
    print(f"  VERDICT: *** CRITICAL — {crashed} crash(es) found ***")
elif security_findings:
    print(f"  VERDICT: *** WARNING — {len(security_findings)} security finding(s) ***")
elif failed:
    print(f"  VERDICT: SOME FAILURES — {failed} test(s) did not match expected output")
else:
    print(f"  VERDICT: ALL {passed} TESTS PASSED — no crashes, no security findings")
print(SEP)

# Write machine-readable results
out_file = "fuzz_results.jsonl"
with open(out_file, "w", encoding="utf-8") as f:
    for r in results:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"\n  Detailed results written to {out_file}", file=sys.stderr)