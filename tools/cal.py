#!/usr/bin/env python3
"""
Encrypted calendar — command-line tool.

The calendar lives in data/calendar.enc.json, encrypted with a password
(AES-256-GCM, key from PBKDF2-SHA256). The web app and this tool use the same
format, so either can read what the other wrote. All labels, types, colours and
names live inside the encrypted data (under "settings"), not in this code.

Commands
  decrypt            data/calendar.enc.json  -> calendar.json   (plaintext, git-ignored)
  encrypt            calendar.json           -> data/calendar.enc.json
  check              validate calendar.json
  summary            print what is coming up in the next N days (default 21)
  export-xlsx OUT    a spreadsheet snapshot (values, not formulas); never commit it
  passwd             re-encrypt with a new password
  make-setup OUT     calendar.json -> a one-time setup file for a fresh repository,
                     locked with a random setup code (printed). Hand both to the owner
                     privately; the site's setup screen re-locks it with their own
                     password, so the repository never holds a copy under a shared code.

Password: read from the CAL_PASSWORD environment variable, otherwise prompted.
"""
import argparse, base64, datetime as dt, getpass, json, os, re, secrets, sys, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENC = ROOT / "data" / "calendar.enc.json"
PLAIN = ROOT / "calendar.json"
ITERATIONS = 600_000
FORMAT = "encrypted-calendar"

TRIPWIRE_STATUSES = ["Open", "On track", "At risk", "Met", "Missed"]
PREMORTEM_STATUSES = ["Open", "Guard in place", "Watching", "Happened", "Closed"]
DEFAULT_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


# ---------------------------------------------------------------- crypto
def _b64(b): return base64.b64encode(b).decode()
def _unb64(s): return base64.b64decode(s)


def _key(password: str, salt: bytes, iterations: int) -> bytes:
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)


def encrypt_obj(obj: dict, password: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    plaintext = json.dumps(obj, ensure_ascii=False, indent=1).encode("utf-8")
    ct = AESGCM(_key(password, salt, ITERATIONS)).encrypt(iv, plaintext, None)  # ciphertext || tag, as WebCrypto
    return {"format": FORMAT, "v": 1, "kdf": "PBKDF2-SHA256", "iterations": ITERATIONS,
            "cipher": "AES-256-GCM", "salt": _b64(salt), "iv": _b64(iv), "ct": _b64(ct)}


def decrypt_obj(env: dict, password: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    key = _key(password, _unb64(env["salt"]), int(env["iterations"]))
    try:
        pt = AESGCM(key).decrypt(_unb64(env["iv"]), _unb64(env["ct"]), None)
    except InvalidTag:
        sys.exit("Wrong password (or the file is damaged).")
    return json.loads(pt.decode("utf-8"))


def get_password(confirm=False, prompt="Calendar password: "):
    pw = os.environ.get("CAL_PASSWORD")
    if pw:
        return pw
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat: ") != pw:
        sys.exit("Passwords did not match.")
    return pw


# ---------------------------------------------------------------- helpers
def parse_date(s):
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return None
    try:
        return dt.date.fromisoformat(s)
    except ValueError:
        return None


def new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def touch(data):
    data["updatedAt"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["updatedBy"] = os.environ.get("CAL_EDITOR", "Claude (cal.py)")


def settings(data):
    return data.get("settings", {})


def event_types(data):
    return [t["name"] for t in settings(data).get("eventTypes", [])] or ["Event"]


def day_names(data):
    names = settings(data).get("dayNames")
    return names if isinstance(names, list) and len(names) == 7 else DEFAULT_DAYS


# ---------------------------------------------------------------- check
def check(data) -> list:
    errs, types = [], event_types(data)
    for e in data.get("events", []):
        if not parse_date(e.get("date")):
            errs.append(f"Event {e.get('item')!r}: bad date {e.get('date')!r}")
        if e.get("until") and not parse_date(e["until"]):
            errs.append(f"Event {e.get('item')!r}: bad until {e.get('until')!r}")
        if e.get("until") and parse_date(e["until"]) and parse_date(e.get("date")) and parse_date(e["until"]) < parse_date(e["date"]):
            errs.append(f"Event {e.get('item')!r}: ends before it starts")
        if e.get("type") not in types:
            errs.append(f"Event {e.get('item')!r}: type {e.get('type')!r} not in settings.eventTypes {types}")
        if not e.get("id"):
            e["id"] = new_id("ev")
    for w in data.get("weeks", []):
        d = parse_date(w.get("start"))
        if not d or d.weekday() != 0:
            errs.append(f"Week {w.get('start')!r}: must be a Monday (YYYY-MM-DD)")
        if len(w.get("days", [])) != 7:
            errs.append(f"Week {w.get('start')!r}: needs 7 day cells")
    for t in data.get("tripwires", []):
        if t.get("status") not in TRIPWIRE_STATUSES:
            errs.append(f"Tripwire {t.get('n')}: status {t.get('status')!r} not in {TRIPWIRE_STATUSES}")
    for p in data.get("premortem", []):
        if p.get("status") not in PREMORTEM_STATUSES:
            errs.append(f"Premortem {p.get('n')}: status {p.get('status')!r} not in {PREMORTEM_STATUSES}")
        for k in ("likelihood", "impact"):
            v = p.get(k)
            if v not in (None, "") and not (isinstance(v, int) and 1 <= v <= 5):
                errs.append(f"Premortem {p.get('n')}: {k} must be 1–5 or empty")
    for coll, prefix in (("months", "mo"), ("tripwires", "tw"), ("premortem", "pm"), ("priorities", "pr"), ("backcast", "bc"), ("focus", "fs")):
        for row in data.get(coll, []):
            row.setdefault("id", new_id(prefix))
    return errs


# ---------------------------------------------------------------- derived (mirrors app.js)
def opening_date(data):
    n = settings(data).get("openingTripwire")
    for t in data.get("tripwires", []):
        if n is not None and t.get("n") == n:
            return parse_date(t.get("by"))
    return None


def events_in_week(data, start: dt.date):
    end = start + dt.timedelta(days=7)
    out = []
    for e in data.get("events", []):
        d = parse_date(e.get("date")); u = parse_date(e.get("until")) or d
        if d and d < end and u >= start:
            out.append(e)
    return out


def summary(data, days=21):
    today = dt.date.today(); horizon = today + dt.timedelta(days=days)
    print(f"{data.get('title', 'Calendar')} — next {days} days from {today:%a %d %b %Y}\n")
    for e in sorted(data["events"], key=lambda e: e["date"]):
        d = parse_date(e["date"]); u = parse_date(e.get("until")) or d
        if u >= today and d <= horizon:
            span = f"{d:%d %b}" + (f"–{u:%d %b}" if u != d else "")
            print(f"  {span:<15} {e['type']:<10} {e['item']}")
    if data.get("tripwires"):
        print("\nTripwires")
        for t in data["tripwires"]:
            d = parse_date(t.get("by"))
            left = f"{(d - today).days} days" if d else t.get("by")
            print(f"  #{t['n']:<2} {t['status']:<9} {left:<14} {t['checkpoint']}")


# ---------------------------------------------------------------- export
def export_xlsx(data, out):
    import openpyxl
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    wb = openpyxl.Workbook(); wb.remove(wb.active)
    head_fill, head_font = PatternFill("solid", fgColor="2E3440"), Font(name="Arial", bold=True, color="FFFFFF", size=10)
    body = Font(name="Arial", size=10)
    today = dt.date.today(); opening = opening_date(data); st = settings(data)
    short = st.get("countdownShort", "target")

    def sheet(name, meta_key, headers, rows, widths, date_cols=()):
        ws = wb.create_sheet(name)
        meta = data.get("sheets", {}).get(meta_key, {})
        ws["A1"] = meta.get("title", name); ws["A1"].font = Font(name="Arial", bold=True, size=14)
        ws["A2"] = meta.get("note", ""); ws["A2"].font = Font(name="Arial", italic=True, size=9)
        for i, h in enumerate(headers, 1):
            c = ws.cell(4, i, h); c.fill, c.font = head_fill, head_font
        for r, row in enumerate(rows, 5):
            for i, v in enumerate(row, 1):
                d = parse_date(v) if (i in date_cols) else None
                c = ws.cell(r, i, d if d else v); c.font = body
                c.alignment = Alignment(wrap_text=True, vertical="top")
                if d: c.number_format = "d mmm yyyy"
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        ws.freeze_panes = "A5"
        return ws

    ev = sorted(data["events"], key=lambda e: e["date"])
    sheet("Events", "events", ["Date", "Until", "Item", "Type", "Source"],
          [[e["date"], e.get("until") or e["date"], e["item"], e["type"], e.get("source", "")] for e in ev],
          [13, 13, 70, 12, 40], date_cols=(1, 2))
    rows, gate_type = [], st.get("gateType", "Gate")
    for w in data["weeks"]:
        s = parse_date(w["start"]); evs = events_in_week(data, s)
        gate = gate_type if any(e["type"] == gate_type for e in evs) else ""
        wk = int((opening - s).days // 7) if opening and opening >= s else ""
        rows.append([w["start"], f"{s:%b %Y}", *w["days"], "; ".join(e["item"] for e in evs), gate, wk, w.get("notes", "")])
    sheet("Weeks", "weeks", ["Week of (Mon)", "Month", *day_names(data), "Fixed this week (from Events)", f"{gate_type}?", f"Weeks to {short}", "Your notes"],
          rows, [13, 10] + [16] * 7 + [50, 7, 9, 40], date_cols=(1,))
    mc = data.get("monthColumns", [])
    sheet("Months", "months", [c["label"] for c in mc], [[m.get(c["key"], "") for c in mc] for m in data.get("months", [])],
          [10, 30, 30, 30, 25, 25, 40, 22])
    sheet("Tripwires", "tripwires", ["#", "Checkpoint", "By", "Where the date comes from", "If it's missed", "Days left", "Status"],
          [[t["n"], t["checkpoint"], t["by"], t["byNote"], t["ifMissed"],
            (parse_date(t["by"]) - today).days if parse_date(t["by"]) else "", t["status"]] for t in data.get("tripwires", [])],
          [4, 40, 13, 40, 40, 9, 11], date_cols=(3,))
    sheet("Premortem", "premortem", ["#", "How it failed", "Why it's plausible", "Luck or decision", "Guard to put in place now",
                                     "Source", "Likelihood (1–5)", "Impact (1–5)", "Score", "Owner", "Status", "Notes"],
          [[p["n"], p["how"], p["why"], p["luck"], p["guard"], p["source"], p.get("likelihood") or "", p.get("impact") or "",
            (p["likelihood"] * p["impact"]) if p.get("likelihood") and p.get("impact") else "", p["owner"], p["status"], p["notes"]]
           for p in data.get("premortem", [])], [4, 30, 45, 12, 45, 30, 10, 10, 7, 12, 13, 30])
    sheet("Priorities", "priorities", ["Rank", "Work", "Form", "Condition or cap", "Funder", "Due"],
          [[p["rank"], p["work"], p["form"], p["condition"], p["funder"], p["due"]] for p in data.get("priorities", [])],
          [6, 25, 45, 45, 30, 18])
    sheet("Backcast", "backcast", ["When", "What happened", "Tripwire #"],
          [[b["when"], b["what"], b["tripwire"]] for b in data.get("backcast", [])], [18, 60, 10])
    ws = wb.create_sheet("Focus flow")
    ws["A1"] = data.get("sheets", {}).get("focus", {}).get("title", "Focus flow"); ws["A1"].font = Font(name="Arial", bold=True, size=14)
    r = 4
    for s in data.get("focus", []):
        ws.cell(r, 2, s["title"]).font = Font(name="Arial", bold=True, size=11); r += 1
        for i, step in enumerate(s["steps"], 1):
            ws.cell(r, 1, i).font = body; c = ws.cell(r, 2, step); c.font = body; c.alignment = Alignment(wrap_text=True); r += 1
    ws.column_dimensions["A"].width = 4; ws.column_dimensions["B"].width = 100
    wb.save(out)


# ---------------------------------------------------------------- main
def load_plain():
    if not PLAIN.exists():
        sys.exit(f"{PLAIN.name} not found — run `decrypt` first.")
    return json.loads(PLAIN.read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("decrypt"); sub.add_parser("encrypt"); sub.add_parser("check"); sub.add_parser("passwd")
    s = sub.add_parser("summary"); s.add_argument("--days", type=int, default=21)
    s = sub.add_parser("export-xlsx"); s.add_argument("out")
    s = sub.add_parser("make-setup"); s.add_argument("out")
    a = ap.parse_args()

    if a.cmd == "decrypt":
        data = decrypt_obj(json.loads(ENC.read_text()), get_password())
        PLAIN.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"Decrypted to {PLAIN.name} ({len(data.get('events', []))} events, {len(data.get('weeks', []))} weeks). Do not commit it.")
    elif a.cmd == "encrypt":
        data = load_plain(); errs = check(data)
        if errs:
            sys.exit("Not encrypted — fix these first:\n  " + "\n  ".join(errs))
        touch(data)
        ENC.parent.mkdir(exist_ok=True)
        ENC.write_text(json.dumps(encrypt_obj(data, get_password()), indent=1))
        PLAIN.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"Encrypted to {ENC.relative_to(ROOT)}. Commit and push it, then delete {PLAIN.name}.")
    elif a.cmd == "check":
        errs = check(load_plain())
        print("OK" if not errs else "Problems:\n  " + "\n  ".join(errs)); sys.exit(1 if errs else 0)
    elif a.cmd == "summary":
        data = load_plain() if PLAIN.exists() else decrypt_obj(json.loads(ENC.read_text()), get_password())
        summary(data, a.days)
    elif a.cmd == "export-xlsx":
        data = load_plain() if PLAIN.exists() else decrypt_obj(json.loads(ENC.read_text()), get_password())
        export_xlsx(data, a.out); print(f"Wrote {a.out}")
    elif a.cmd == "make-setup":
        data = load_plain(); errs = check(data)
        if errs:
            sys.exit("Fix these first:\n  " + "\n  ".join(errs))
        code = "-".join(secrets.token_hex(3) for _ in range(4))
        Path(a.out).write_text(json.dumps(encrypt_obj(data, code), indent=1))
        print(f"Wrote {a.out}. Setup code: {code}\nNever commit the setup file.")
    elif a.cmd == "passwd":
        old = decrypt_obj(json.loads(ENC.read_text()), get_password(prompt="Current password: "))
        os.environ.pop("CAL_PASSWORD", None)
        new = get_password(confirm=True, prompt="New password: ")
        touch(old); ENC.write_text(json.dumps(encrypt_obj(old, new), indent=1))
        print("Re-encrypted with the new password. Commit and push data/calendar.enc.json.")


if __name__ == "__main__":
    main()
