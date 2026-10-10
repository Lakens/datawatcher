#!/usr/bin/env python3
"""Check a datawatcher log, independently of the datawatcher program.

Uses only the Python standard library.

    python check_log.py chain.jsonl
    python check_log.py chain.jsonl --data path/to/data/folder
    python check_log.py chain.jsonl --online
    python check_log.py chain.jsonl --receipts receipts_folder

Without options it checks that every entry is correctly linked to the one
before it and prints a summary. --data compares the files in a folder with
the log and gives, for each file, the time window in which that exact version
was logged. --online compares every beacon value in the log with the public
NIST and drand archives. --receipts saves the RFC 3161 timestamp receipts as
.tsr files and prints the openssl commands that check their signatures, and
saves the OpenTimestamps proofs as .ots files with the entries they cover.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime


# Standard header of an OpenTimestamps proof file.
OTS_HEADER = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


def parse_time(s):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def fmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S UTC") if t else "unknown"


def load(path):
    data = open(path, "rb").read()
    if not data.endswith(b"\n"):
        sys.exit("FAILED: the last line is incomplete")
    lines = data[:-1].split(b"\n")
    entries, prev = [], ""
    for i, line in enumerate(lines):
        e = json.loads(line)
        if e["seq"] != i:
            sys.exit(f"FAILED: line {i + 1} has number {e['seq']}, expected {i}")
        if e["prev"] != prev:
            sys.exit(f"FAILED: entry {i} does not link to the entry before it")
        e["_hash"] = prev = hashlib.sha256(line).hexdigest()
        e["_line"] = line
        entries.append(e)
    return entries


def lower_bound(e):
    """The entry cannot have been written before its beacon values existed."""
    times = []
    if e.get("nist"):
        times.append(parse_time(e["nist"]["time"]))
    if e.get("drand"):
        times.append(parse_time(e["drand"]["time"]))
    return max(times) if times else None


def upper_bounds(entries):
    """For each entry, the earliest RFC 3161 receipt time covering it."""
    receipts = []  # (anchored_seq, time, service)
    for e in entries:
        for a in e.get("anchors", []):
            if a["anchored_hash"] != entries[a["anchored_seq"]]["_hash"]:
                sys.exit(f"FAILED: a receipt in entry {e['seq']} names the wrong fingerprint for entry {a['anchored_seq']}")
            if a["kind"] == "rfc3161":
                receipts.append((a["anchored_seq"], parse_time(a["time"]), a["service"]))
    out = {}
    for e in entries:
        covering = [(t, s) for seq, t, s in receipts if seq >= e["seq"]]
        out[e["seq"]] = min(covering) if covering else (None, None)
    return out


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "check_log.py", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--data", help="folder whose files should be compared with the log")
    ap.add_argument("--online", action="store_true", help="compare beacon values with the public archives")
    ap.add_argument("--receipts", help="folder in which to save the timestamp receipts and proofs")
    args = ap.parse_args()

    entries = load(args.log)
    ub = upper_bounds(entries)
    print(f"OK: all {len(entries)} entries are correctly linked.")
    print(f"First entry fingerprint (compare with the preregistration): {entries[0]['_hash']}")
    print(f"Last entry fingerprint:  {entries[-1]['_hash']}")

    start = entries[0]
    print(f"Log started for ORCID {start.get('orcid')}, folder '{start.get('folder')}', with {start.get('tool')}")
    sessions = [e for e in entries if e["type"] == "session_start"]
    ends = sum(1 for e in entries if e["type"] == "session_end")
    print(f"Sessions: {len(sessions)} started, {ends} ended normally")
    for e in entries:
        if e["type"] == "session_start" and e.get("note"):
            print(f"  Note at entry {e['seq']}: {e['note']}")
    unanchored = [e["seq"] for e in entries if e["type"] != "timestamp" and ub[e["seq"]][0] is None]
    if unanchored:
        print(f"  Entries without any receipt yet: {unanchored}")
    missing_beacons = [e["seq"] for e in entries if lower_bound(e) is None and e["type"] != "timestamp"]
    if missing_beacons:
        print(f"  Entries without beacon values: {missing_beacons}")

    print("\nFile history (time window: written after .. existed by):")
    for e in entries:
        if e["type"] in ("file_added", "file_changed", "file_removed"):
            t2, svc = ub[e["seq"]]
            flag = "  [happened while not watching]" if e.get("found_at_startup") else ""
            sha = (e.get("sha256") or "")[:12]
            print(f"  {e['seq']:>5} {e['type'][5:]:<8} {e['path']:<30} {sha:<12} {fmt(lower_bound(e))} .. {fmt(t2)}{flag}")

    if args.data:
        print(f"\nFiles in {args.data}:")
        versions = {}
        for e in entries:
            if e.get("sha256"):
                versions.setdefault((e["path"], e["sha256"]), e)
        bad = 0
        for root, dirs, files in os.walk(args.data):
            dirs[:] = [d for d in dirs if d not in (".provenance", ".git")]
            for name in sorted(files):
                p = os.path.join(root, name)
                rel = os.path.relpath(p, args.data).replace(os.sep, "/")
                sha = sha256_file(p)
                e = versions.get((rel, sha))
                if e is None:
                    match = [x for (path, s), x in versions.items() if s == sha]
                    if match:
                        e = match[0]
                        print(f"  {rel}: same content as '{e['path']}' (entry {e['seq']})")
                        continue
                    print(f"  {rel}: NOT IN THE LOG (this version was never logged)")
                    bad += 1
                    continue
                t2, svc = ub[e["seq"]]
                print(f"  {rel}: logged in entry {e['seq']}, written after {fmt(lower_bound(e))}, existed by {fmt(t2)} ({svc})")
        if bad:
            print(f"WARNING: {bad} file(s) do not match any logged version.")

    if args.online:
        print("\nComparing beacon values with the public archives...")
        seen, problems = set(), 0
        for e in entries:
            for kind in ("nist", "drand"):
                b = e.get(kind)
                if not b:
                    continue
                key = (kind, b.get("uri") or b.get("round"))
                if key in seen:
                    continue
                seen.add(key)
                try:
                    if kind == "nist":
                        p = get_json(b["uri"])["pulse"]
                        ok = p["outputValue"] == b["output_value"] and parse_time(p["timeStamp"]) == parse_time(b["time"])
                    else:
                        p = get_json(f"https://api.drand.sh/{b['chain']}/public/{b['round']}")
                        ok = p["randomness"] == b["randomness"]
                except Exception as ex:  # network problems are reported, not fatal
                    print(f"  could not check {kind} {key[1]}: {ex}")
                    continue
                if not ok:
                    problems += 1
                    print(f"  MISMATCH: {kind} value in entry {e['seq']} differs from the public archive")
        print(f"  checked {len(seen)} beacon values, {problems} mismatches")

    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        print(f"\nReceipts saved in {args.receipts}. Check each with openssl:")
        for e in entries:
            for a in e.get("anchors", []):
                if a["kind"] == "opentimestamps":
                    name = f"entry-{a['anchored_seq']:06d}.txt"
                    with open(os.path.join(args.receipts, name), "wb") as f:
                        f.write(entries[a["anchored_seq"]]["_line"])
                    with open(os.path.join(args.receipts, name + ".ots"), "wb") as f:
                        f.write(OTS_HEADER + bytes([1, 8]) + bytes.fromhex(a["anchored_hash"]) + base64.b64decode(a["receipt"]))
                    print(f"  {name} + {name}.ots: OpenTimestamps proof; check at https://opentimestamps.org")
                    continue
                name = f"entry{a['anchored_seq']}-{a['service']}.tsr"
                with open(os.path.join(args.receipts, name), "wb") as f:
                    f.write(base64.b64decode(a["receipt"]))
                print(f"  openssl ts -verify -in {name} -digest {a['anchored_hash']} -CAfile <CA file> -untrusted <service certificates>")


if __name__ == "__main__":
    main()
