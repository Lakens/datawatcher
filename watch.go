package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The folder is checked by listing it every few seconds rather than by
// asking the operating system for change notifications. This works the same
// on every system and on network drives, and needs no outside libraries.

type fileStat struct {
	size int64
	mod  time.Time
}

func (a fileStat) same(b fileStat) bool { return a.size == b.size && a.mod.Equal(b.mod) }

type change struct {
	kind string // file_added, file_changed or file_removed
	path string // relative to the watched folder, with forward slashes
	sha  string
	stat fileStat
}

type watcher struct {
	root      string
	skipPaths map[string]bool
	lastScan  map[string]fileStat
	hashedAt  map[string]fileStat // size and time when last hashed
	missing   map[string]int      // number of scans in a row a logged file was absent
	warned    map[string]bool
}

func newWatcher(root string) *watcher {
	return &watcher{
		root:      root,
		skipPaths: map[string]bool{},
		lastScan:  map[string]fileStat{},
		hashedAt:  map[string]fileStat{},
		missing:   map[string]int{},
		warned:    map[string]bool{},
	}
}

// Files that operating systems and office programs create on their own.
func skipName(name string) bool {
	switch strings.ToLower(name) {
	case "thumbs.db", "desktop.ini", ".ds_store":
		return true
	}
	return strings.HasPrefix(name, "~$") || strings.HasPrefix(name, "._")
}

func (w *watcher) warnOnce(key, msg string) {
	if !w.warned[key] {
		w.warned[key] = true
		fmt.Println("  Warning:", msg)
	}
}

// scan lists all regular files with their size and modification time. It
// returns an error when the folder itself cannot be read, so that a
// disconnected drive is not mistaken for all files being removed.
func (w *watcher) scan() (map[string]fileStat, error) {
	if info, err := os.Stat(w.root); err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a folder")
		}
		return nil, err
	}
	out := map[string]fileStat{}
	err := filepath.WalkDir(w.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == w.root {
				return err
			}
			w.warnOnce(p, fmt.Sprintf("cannot read %s: %v", p, err))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == w.root {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == provDirName || name == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || skipName(name) {
			return nil
		}
		rel, err := filepath.Rel(w.root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if w.skipPaths[rel] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out[rel] = fileStat{size: info.Size(), mod: info.ModTime()}
		return nil
	})
	return out, err
}

// hashStable returns the SHA-256 of a file, or false when the file could not
// be read or changed while it was being read.
func (w *watcher) hashStable(rel string, before fileStat) (string, bool) {
	p := filepath.Join(w.root, filepath.FromSlash(rel))
	f, err := os.Open(p)
	if err != nil {
		return "", false // often a file another program still has open
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return "", false
	}
	info, err := os.Stat(p)
	if err != nil || !before.same(fileStat{info.Size(), info.ModTime()}) {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// fullCheck hashes every file now and compares it with the log. It is used
// when a session starts (to find changes made while nothing was watching)
// and when it ends (to catch changes too recent to have settled).
func (w *watcher) fullCheck(logged map[string]fileState) ([]change, error) {
	cur, err := w.scan()
	if err != nil {
		return nil, err
	}
	var out []change
	for path, st := range cur {
		if h, ok := w.hashedAt[path]; ok && h.same(st) {
			continue
		}
		sum, ok := w.hashStable(path, st)
		if !ok {
			continue
		}
		w.hashedAt[path] = st
		out = appendIfChanged(out, logged, path, sum, st)
	}
	for path := range logged {
		if _, ok := cur[path]; !ok {
			out = append(out, change{kind: "file_removed", path: path})
		}
	}
	w.forget(cur)
	w.lastScan = cur
	sortChanges(out)
	return out, nil
}

// poll compares the folder with the previous listing. A file is hashed only
// once its size and time have stayed the same between two listings, so that
// a file still being written is not logged half-finished. A logged file
// counts as removed only after it is absent from two listings in a row,
// because some programs save by deleting and then re-creating a file.
func (w *watcher) poll(logged map[string]fileState) ([]change, error) {
	cur, err := w.scan()
	if err != nil {
		return nil, err
	}
	var out []change
	for path, st := range cur {
		delete(w.missing, path)
		if h, ok := w.hashedAt[path]; ok && h.same(st) {
			continue
		}
		if prev, ok := w.lastScan[path]; !ok || !prev.same(st) {
			continue // still changing; look again next time
		}
		sum, ok := w.hashStable(path, st)
		if !ok {
			continue
		}
		w.hashedAt[path] = st
		out = appendIfChanged(out, logged, path, sum, st)
	}
	for path := range logged {
		if _, ok := cur[path]; ok {
			continue
		}
		w.missing[path]++
		if w.missing[path] >= 2 {
			out = append(out, change{kind: "file_removed", path: path})
			delete(w.missing, path)
		}
	}
	w.forget(cur)
	w.lastScan = cur
	sortChanges(out)
	return out, nil
}

func appendIfChanged(out []change, logged map[string]fileState, path, sum string, st fileStat) []change {
	old, known := logged[path]
	if known && old.SHA256 == sum {
		return out
	}
	kind := "file_added"
	if known {
		kind = "file_changed"
	}
	return append(out, change{kind: kind, path: path, sha: sum, stat: st})
}

func (w *watcher) forget(cur map[string]fileStat) {
	for path := range w.hashedAt {
		if _, ok := cur[path]; !ok {
			delete(w.hashedAt, path)
		}
	}
}

func sortChanges(cs []change) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].path < cs[j].path })
}
