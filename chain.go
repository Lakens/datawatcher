package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const (
	toolName    = "datawatcher"
	toolVersion = "0.1.1"
	provDirName = ".provenance"
	chainName   = "chain.jsonl"
)

// Entry is one line of the log file. The fingerprint of an entry is the
// SHA-256 of its exact line bytes (without the newline). Each entry stores the
// fingerprint of the entry before it in Prev, so changing, removing or
// reordering any earlier line breaks every later link.
type Entry struct {
	Seq       int    `json:"seq"`
	Type      string `json:"type"`
	Prev      string `json:"prev"`
	LocalTime string `json:"local_time"`
	Session   string `json:"session"`

	// Written in chain_start and session_start entries.
	ORCID    string `json:"orcid,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Platform string `json:"platform,omitempty"`
	Folder   string `json:"folder,omitempty"`

	// Written in file_added, file_changed and file_removed entries.
	Path           string `json:"path,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Size           *int64 `json:"size,omitempty"`
	FileModified   string `json:"file_modified,omitempty"`
	FoundAtStartup bool   `json:"found_at_startup,omitempty"`

	// Written in timestamp entries.
	Anchors []Anchor `json:"anchors,omitempty"`

	Note string `json:"note,omitempty"`

	// Public random values that did not exist before they were published,
	// so this entry cannot have been written before those times.
	NIST        *NISTPulse  `json:"nist,omitempty"`
	Drand       *DrandRound `json:"drand,omitempty"`
	BeaconError string      `json:"beacon_error,omitempty"`
}

// Anchor is a receipt from an outside service showing that the entry with
// fingerprint AnchoredHash (and through the links, every entry before it)
// existed by the time the service recorded it.
type Anchor struct {
	Kind         string `json:"kind"` // "rfc3161" or "opentimestamps"
	Service      string `json:"service"`
	AnchoredSeq  int    `json:"anchored_seq"`
	AnchoredHash string `json:"anchored_hash"`
	Time         string `json:"time,omitempty"` // time stated in an RFC 3161 receipt
	Receipt      string `json:"receipt"`        // base64
}

type fileState struct {
	SHA256 string
}

// Chain is the log file plus what can be derived from reading it.
type Chain struct {
	path      string
	nextSeq   int
	firstHash string // fingerprint of entry 0; names the log
	lastHash  [32]byte
	lastLine  []byte

	files           map[string]fileState // last logged version of each file
	sessionOpen     bool                 // last session has no session_end entry
	lastContentSeq  int                  // last entry that is not a timestamp entry
	lastAnchoredSeq int                  // highest entry covered by an RFC 3161 receipt
	lastOTSSeq      int                  // highest entry covered by an OpenTimestamps receipt
}

func entryHash(line []byte) string {
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

// loadChain reads the log and checks every link. It refuses to continue
// when the log has been altered, rather than appending to a broken chain.
func loadChain(path string) (*Chain, error) {
	c := &Chain{path: path, files: map[string]fileState{}, lastContentSeq: -1, lastAnchoredSeq: -1, lastOTSSeq: -1}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return c, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("the last line of %s is incomplete, probably because the computer stopped while writing it; it has not been changed", path)
	}
	for i, line := range bytes.Split(data[:len(data)-1], []byte("\n")) {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("line %d of %s cannot be read: %v", i+1, path, err)
		}
		if e.Seq != i {
			return nil, fmt.Errorf("line %d of %s has number %d instead of %d; the log has been changed", i+1, path, e.Seq, i)
		}
		want := ""
		if i > 0 {
			want = hex.EncodeToString(c.lastHash[:])
		}
		if e.Prev != want {
			return nil, fmt.Errorf("entry %d in %s does not match the entry before it; the log has been changed", i, path)
		}
		c.apply(&e)
		c.lastHash = sha256.Sum256(line)
		c.lastLine = line
		c.nextSeq = i + 1
		if i == 0 {
			c.firstHash = entryHash(line)
		}
	}
	return c, nil
}

func (c *Chain) apply(e *Entry) {
	switch e.Type {
	case "file_added", "file_changed":
		c.files[e.Path] = fileState{SHA256: e.SHA256}
	case "file_removed":
		delete(c.files, e.Path)
	case "session_start":
		c.sessionOpen = true
	case "session_end":
		c.sessionOpen = false
	case "timestamp":
		for _, a := range e.Anchors {
			if a.Kind == "rfc3161" && a.AnchoredSeq > c.lastAnchoredSeq {
				c.lastAnchoredSeq = a.AnchoredSeq
			}
			if a.Kind == "opentimestamps" && a.AnchoredSeq > c.lastOTSSeq {
				c.lastOTSSeq = a.AnchoredSeq
			}
		}
	}
	if e.Type != "timestamp" {
		c.lastContentSeq = e.Seq
	}
}

// append numbers the entry, links it to the previous one, and writes it to
// disk before returning.
func (c *Chain) append(e *Entry) error {
	e.Seq = c.nextSeq
	e.Prev = ""
	if c.nextSeq > 0 {
		e.Prev = hex.EncodeToString(c.lastHash[:])
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	c.apply(e)
	c.lastHash = sha256.Sum256(line)
	c.lastLine = line
	if c.nextSeq == 0 {
		c.firstHash = entryHash(line)
	}
	c.nextSeq++
	return nil
}
