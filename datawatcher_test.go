package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeEntries(t *testing.T, path string, n int) *Chain {
	t.Helper()
	c, err := loadChain(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		size := int64(i)
		if err := c.append(&Entry{Type: "file_added", Path: "f" + string(rune('a'+i)), SHA256: "00", Size: &size}); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestChainRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), chainName)
	c := writeEntries(t, path, 4)
	c2, err := loadChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if c2.nextSeq != 4 || c2.lastHash != c.lastHash || len(c2.files) != 4 {
		t.Fatalf("reloaded chain differs: %+v", c2)
	}
	// Appending after reloading continues the same chain.
	if err := c2.append(&Entry{Type: "file_removed", Path: "fa"}); err != nil {
		t.Fatal(err)
	}
	c3, err := loadChain(path)
	if err != nil || c3.nextSeq != 5 || len(c3.files) != 3 {
		t.Fatalf("after removal: %v %+v", err, c3)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, chainName)
	writeEntries(t, path, 4)
	orig, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(orig), "\n"), "\n")

	cases := map[string]string{
		"edited":    strings.Replace(string(orig), `"path":"fb"`, `"path":"fx"`, 1),
		"removed":   strings.Join(append([]string{lines[0]}, lines[2:]...), "\n") + "\n",
		"reordered": strings.Join([]string{lines[0], lines[2], lines[1], lines[3]}, "\n") + "\n",
		"crlf":      strings.ReplaceAll(string(orig), "\n", "\r\n"),
		"truncated": string(orig[:len(orig)-5]),
	}
	for name, content := range cases {
		os.WriteFile(path, []byte(content), 0o644)
		if _, err := loadChain(path); err == nil {
			t.Errorf("%s log was accepted", name)
		}
	}
	// Removing only the last line cannot be detected from the file alone;
	// that is what the outside receipts and public copies are for.
	os.WriteFile(path, []byte(strings.Join(lines[:3], "\n")+"\n"), 0o644)
	if _, err := loadChain(path); err != nil {
		t.Errorf("a shortened but intact log was rejected: %v", err)
	}
}

func TestEntryHashIsLineHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), chainName)
	c := writeEntries(t, path, 2)
	data, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if sha256.Sum256(lines[1]) != c.lastHash {
		t.Fatal("lastHash is not the SHA-256 of the last line")
	}
	if !strings.Contains(string(lines[1]), entryHash(lines[0])) {
		t.Fatal("second entry does not contain the first entry's fingerprint")
	}
}

func TestORCID(t *testing.T) {
	good := []string{"0000-0002-1825-0097", "https://orcid.org/0000-0002-1825-0097", "0000-0002-1694-233x", "0000-0002-0247-239X"}
	for _, s := range good {
		if _, ok := normalizeORCID(s); !ok {
			t.Errorf("%s rejected", s)
		}
	}
	bad := []string{"0000-0002-1825-0098", "0000-0002-1825-009", "abcd-0002-1825-0097", ""}
	for _, s := range bad {
		if _, ok := normalizeORCID(s); ok {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestWatcherSettlesAndDetectsChanges(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, provDirName), 0o755)
	os.WriteFile(filepath.Join(root, provDirName, "chain.jsonl"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "Thumbs.db"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "sub", "a.txt"), []byte("one"), 0o644)

	w := newWatcher(root)
	logged := map[string]fileState{}
	apply := func(cs []change) {
		for _, c := range cs {
			if c.kind == "file_removed" {
				delete(logged, c.path)
			} else {
				logged[c.path] = fileState{c.sha}
			}
		}
	}

	cs, err := w.fullCheck(logged)
	if err != nil || len(cs) != 1 || cs[0].kind != "file_added" || cs[0].path != "sub/a.txt" {
		t.Fatalf("startup check: %v %+v", err, cs)
	}
	apply(cs)

	// A new file is logged only after it has stayed the same for one poll.
	os.WriteFile(filepath.Join(root, "b.txt"), []byte("two"), 0o644)
	if cs, _ := w.poll(logged); len(cs) != 0 {
		t.Fatalf("unsettled file logged: %+v", cs)
	}
	cs, _ = w.poll(logged)
	if len(cs) != 1 || cs[0].path != "b.txt" || cs[0].kind != "file_added" {
		t.Fatalf("settled file: %+v", cs)
	}
	apply(cs)

	// Same content written again: nothing to log.
	later := time.Now().Add(time.Minute)
	os.Chtimes(filepath.Join(root, "b.txt"), later, later)
	w.poll(logged)
	if cs, _ := w.poll(logged); len(cs) != 0 {
		t.Fatalf("unchanged content logged: %+v", cs)
	}

	// New content.
	os.WriteFile(filepath.Join(root, "b.txt"), []byte("three"), 0o644)
	w.poll(logged)
	cs, _ = w.poll(logged)
	if len(cs) != 1 || cs[0].kind != "file_changed" {
		t.Fatalf("changed file: %+v", cs)
	}
	apply(cs)

	// Removal is logged after two polls without the file.
	os.Remove(filepath.Join(root, "b.txt"))
	if cs, _ := w.poll(logged); len(cs) != 0 {
		t.Fatalf("removal logged too early: %+v", cs)
	}
	cs, _ = w.poll(logged)
	if len(cs) != 1 || cs[0].kind != "file_removed" {
		t.Fatalf("removal: %+v", cs)
	}
	apply(cs)

	// A folder that has disappeared is an error, not a removal of every file.
	os.RemoveAll(root)
	if _, err := w.poll(logged); err == nil {
		t.Fatal("missing folder not reported")
	}
}

func TestOTSProofLayout(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, 32)
	p := otsProof(digest, []byte{0xf0, 0x01})
	if !bytes.HasPrefix(p, otsHeader) || len(otsHeader) != 31 {
		t.Fatalf("header wrong, length %d", len(otsHeader))
	}
	rest := p[len(otsHeader):]
	if rest[0] != 1 || rest[1] != 8 || !bytes.Equal(rest[2:34], digest) {
		t.Fatal("layout wrong")
	}
}
