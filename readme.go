package main

import "encoding/json"

func jsonUnmarshalString(s string, out any) { json.Unmarshal([]byte(s), out) }

// readmeText is saved next to the log and uploaded with it to Zenodo, so
// that anyone who finds the log can check it without this program.
const readmeText = `FILE PROVENANCE LOG
===================

This folder was written by datawatcher. It records every version of every
file in the watched folder, in a way that makes later changes to the record
detectable. Do not edit or delete anything in this folder.

chain.jsonl
  The log. Each line is one entry in JSON format. The fingerprint of an entry
  is the SHA-256 of its exact line (without the line break). Each entry's
  "prev" field holds the fingerprint of the line before it ("" for the
  first). Changing, removing or reordering any line therefore breaks every
  link after it.

  Entry types:
    chain_start      first entry; names the folder and the researcher (ORCID)
    session_start    the program was started
    file_added       a new file, with its SHA-256 and size
    file_changed     a new version of a file
    file_removed     a file disappeared
    timestamp        receipts from outside services (see below)
    session_end      the program was stopped
  "found_at_startup": true means the change happened while the program was
  not running, and was found when it started.

How the times are established
  Lower bound: most entries contain the current value of the NIST
  Randomness Beacon ("nist") and of the drand network ("drand"). These are
  unpredictable values published at fixed times, so the entry cannot have
  been written before them. Check them at the "uri" given (NIST) and at
  https://api.drand.sh/<chain>/public/<round> (drand).

  Upper bound: "timestamp" entries hold receipts for the fingerprint of an
  earlier entry ("anchored_seq", "anchored_hash"), which through the links
  covers every entry up to that one.
    kind "rfc3161": a receipt signed by a timestamp service (RFC 3161).
      Save the base64 "receipt" as a binary file r.tsr, then run
        openssl ts -reply -in r.tsr -text
      to read it, and
        openssl ts -verify -in r.tsr -digest <anchored_hash> -CAfile <the service's certificate chain>
      to check the signature.
    kind "opentimestamps": a proof that is recorded in the Bitcoin
      blockchain within a few hours. The script check_log.py (see
      https://github.com/Lakens/datawatcher) saves each proof as an .ots
      file with the entry it covers; check or complete them at
      https://opentimestamps.org. Next to the original log, the folder
      "opentimestamps" holds the same files.

  Every entry therefore lies between a beacon time it cannot precede and a
  receipt time it cannot follow.

settings.json
  Settings of the program (ORCID, repository names). Not part of the log.
`
