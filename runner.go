package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type runner struct {
	folder, prov string
	chain        *Chain
	settings     *folderSettings
	cfg          *userConfig
	iv           intervals
	session      string
	beacons      *beaconSource
	watcher      *watcher
	github       *githubClient

	pushedSeq     int
	lastPush      time.Time
	lastAnchor    time.Time
	lastOTS       time.Time
	certsReceived map[string]bool
	folderProblem bool
}

func newRunner(folder, prov string, chain *Chain, st *folderSettings, cfg *userConfig, iv intervals) (*runner, error) {
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	r := &runner{
		folder: folder, prov: prov, chain: chain, settings: st, cfg: cfg, iv: iv,
		session:       hex.EncodeToString(id),
		beacons:       &beaconSource{maxAge: 20 * time.Second},
		watcher:       newWatcher(folder),
		pushedSeq:     -1,
		certsReceived: map[string]bool{},
	}
	// Do not log this program itself if it was placed in the watched folder.
	if exe, err := os.Executable(); err == nil {
		if rel, err := filepath.Rel(folder, exe); err == nil && !strings.HasPrefix(rel, "..") {
			r.watcher.skipPaths[filepath.ToSlash(rel)] = true
		}
	}
	return r, nil
}

func (r *runner) logEntry(e *Entry, withBeacons bool) error {
	e.Session = r.session
	e.LocalTime = time.Now().Format(time.RFC3339)
	if withBeacons {
		e.NIST, e.Drand, e.BeaconError = r.beacons.current()
	}
	return r.chain.append(e)
}

func (r *runner) logChanges(cs []change, atStartup bool) error {
	for _, c := range cs {
		e := &Entry{Type: c.kind, Path: c.path, FoundAtStartup: atStartup}
		if c.kind != "file_removed" {
			size := c.stat.size
			e.SHA256, e.Size, e.FileModified = c.sha, &size, c.stat.mod.UTC().Format(time.RFC3339Nano)
		}
		if err := r.logEntry(e, true); err != nil {
			return err
		}
		label := map[string]string{"file_added": "added  ", "file_changed": "changed", "file_removed": "removed"}[c.kind]
		extra := ""
		if c.sha != "" {
			extra = "  " + c.sha[:12]
		}
		if atStartup {
			extra += "  (happened while nothing was watching)"
		}
		fmt.Printf("%s  %s  %s%s\n", time.Now().Format("15:04:05"), label, c.path, extra)
		if e.BeaconError != "" {
			fmt.Println("  Note:", e.BeaconError)
		}
	}
	return nil
}

func (r *runner) runSession(con *console) error {
	newLog := r.chain.nextSeq == 0
	if newLog {
		err := r.logEntry(&Entry{
			Type: "chain_start", ORCID: r.settings.ORCID, Tool: toolName + " " + toolVersion,
			Platform: runtime.GOOS + "/" + runtime.GOARCH, Folder: filepath.Base(r.folder),
		}, true)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(r.prov, "README.txt"), []byte(readmeText), 0o644); err != nil {
			fmt.Println("  Warning: could not write README.txt:", err)
		}
	}

	fmt.Println("Watching:", r.folder)
	fmt.Println("Log:     ", r.chain.path)
	r.startGitHub()
	if r.settings.ZenodoEnabled {
		if *r.cfg.zenodoToken(r.settings.ZenodoSandbox) == "" {
			fmt.Println("Zenodo:   OFF, because no Zenodo token is stored on this computer")
		} else {
			fmt.Println("Zenodo:   you will be asked at the end of the session")
		}
	}
	fmt.Println()

	if newLog {
		fmt.Println("Started a new log. The fingerprint of its first entry is")
		fmt.Println("  " + r.chain.firstHash)
		fmt.Println("Put this fingerprint in your preregistration, so that this log is the only one that counts for the study.")
		fmt.Println()
	}
	start := &Entry{
		Type: "session_start", ORCID: r.settings.ORCID, Tool: toolName + " " + toolVersion,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	if r.chain.sessionOpen {
		start.Note = "the previous session ended without a session_end entry (the program was closed or the computer stopped)"
	}
	if err := r.logEntry(start, true); err != nil {
		return err
	}
	if start.BeaconError != "" {
		fmt.Println("Note:", start.BeaconError)
	}

	fmt.Println("Checking the files already in the folder...")
	changes, err := r.watcher.fullCheck(r.chain.files)
	if err != nil {
		return fmt.Errorf("cannot read the folder: %w", err)
	}
	if err := r.logChanges(changes, true); err != nil {
		return err
	}
	fmt.Printf("%d files are in the log. Watching for changes.\n", len(r.chain.files))
	fmt.Println(`Type stop and press Enter to end the session.`)
	fmt.Println()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	lines := con.lines
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if err := r.pollOnce(); err != nil {
				return err
			}
			r.maybeAnchor(false)
			r.maybePush(false)
		case line, ok := <-lines:
			if !ok {
				lines = nil // no keyboard (for example when run by another program)
				con.closed = true
				continue
			}
			if s := strings.ToLower(strings.TrimSpace(line)); s == "stop" || s == "q" || s == "quit" || s == "exit" {
				return r.finish(con, false)
			}
			fmt.Println(`Type stop and press Enter to end the session.`)
		case s := <-sigs:
			// Ctrl+C ends the session normally. Closing the window or shutting
			// down leaves only a few seconds, so then only the end is recorded.
			return r.finish(con, s != os.Interrupt)
		}
	}
}

// startGitHub prepares the GitHub upload, or says clearly why there is none.
func (r *runner) startGitHub() {
	st := r.settings
	if st.GitHubRepo == "" {
		return
	}
	if r.cfg.GitHubToken == "" {
		fmt.Printf("GitHub:   OFF, because no GitHub token is stored on this computer (repository %s)\n", st.GitHubRepo)
		return
	}
	if st.GitHubPath == "" {
		st.GitHubPath = defaultGitHubPath(r.folder, r.chain.firstHash)
		if err := writeJSON(settingsPath(r.prov), st, 0o644); err != nil {
			fmt.Println("  Warning: could not save the settings:", err)
		}
	}
	r.github = &githubClient{token: r.cfg.GitHubToken, repo: st.GitHubRepo, path: st.GitHubPath}
	fmt.Printf("GitHub:   %s/%s\n", st.GitHubRepo, st.GitHubPath)
	if err := r.github.refresh(); err != nil {
		fmt.Println("  Warning: could not reach GitHub:", err)
	}
}

func (r *runner) pollOnce() error {
	changes, err := r.watcher.poll(r.chain.files)
	if err != nil {
		if !r.folderProblem {
			r.folderProblem = true
			fmt.Println("  Warning: cannot read the folder right now:", err)
		}
		return nil
	}
	if r.folderProblem {
		r.folderProblem = false
		fmt.Println("  The folder can be read again.")
	}
	return r.logChanges(changes, false)
}

// maybeAnchor obtains timestamp receipts for the newest entry, which through
// the links also covers every earlier entry.
func (r *runner) maybeAnchor(force bool) {
	if r.chain.lastContentSeq <= r.chain.lastAnchoredSeq {
		return
	}
	if !force && time.Since(r.lastAnchor) < r.iv.anchor {
		return
	}
	r.lastAnchor = time.Now()
	wantOTS := r.chain.lastContentSeq > r.chain.lastOTSSeq && (force || time.Since(r.lastOTS) >= r.iv.ots)

	seq := r.chain.nextSeq - 1
	digest := r.chain.lastHash
	hash := hex.EncodeToString(digest[:])
	var anchors []Anchor
	var got []string
	for _, svc := range tsaServices {
		receipt, gen, err := requestTimestamp(svc.URL, digest[:], !r.certsReceived[svc.Name])
		if err != nil {
			fmt.Printf("  Warning: no timestamp from %s: %v\n", svc.Name, err)
			continue
		}
		r.certsReceived[svc.Name] = true
		anchors = append(anchors, Anchor{
			Kind: "rfc3161", Service: svc.Name, AnchoredSeq: seq, AnchoredHash: hash,
			Time: gen.UTC().Format(time.RFC3339Nano), Receipt: base64.StdEncoding.EncodeToString(receipt),
		})
		got = append(got, svc.Name)
	}
	if wantOTS {
		r.lastOTS = time.Now()
		for _, cal := range otsCalendars {
			reply, err := submitOTS(cal, digest[:])
			if err != nil {
				fmt.Printf("  Warning: OpenTimestamps calendar %s: %v\n", cal, err)
				continue
			}
			anchors = append(anchors, Anchor{
				Kind: "opentimestamps", Service: cal, AnchoredSeq: seq, AnchoredHash: hash,
				Receipt: base64.StdEncoding.EncodeToString(reply),
			})
			r.writeOTSFiles(seq, digest[:], reply)
			got = append(got, "OpenTimestamps")
			break
		}
	}
	if len(anchors) == 0 {
		return
	}
	if err := r.logEntry(&Entry{Type: "timestamp", Anchors: anchors}, true); err != nil {
		fmt.Println("  Warning: could not write the timestamp entry:", err)
		return
	}
	fmt.Printf("%s  timestamped entries up to %d (%s)\n", time.Now().Format("15:04:05"), seq, strings.Join(got, ", "))
}

// writeOTSFiles saves the anchored entry and its OpenTimestamps proof as a
// pair of files that the standard OpenTimestamps tools can check directly.
// The same proof is also stored inside the log itself.
func (r *runner) writeOTSFiles(seq int, digest, reply []byte) {
	dir := filepath.Join(r.prov, "opentimestamps")
	base := filepath.Join(dir, fmt.Sprintf("entry-%06d.txt", seq))
	err := os.MkdirAll(dir, 0o755)
	if err == nil {
		err = os.WriteFile(base, r.chain.lastLine, 0o644)
	}
	if err == nil {
		err = os.WriteFile(base+".ots", otsProof(digest, reply), 0o644)
	}
	if err != nil {
		fmt.Println("  Warning: could not save the OpenTimestamps files:", err)
	}
}

func (r *runner) maybePush(force bool) {
	seq := r.chain.nextSeq - 1
	if r.github == nil || seq == r.pushedSeq {
		return
	}
	if !force && time.Since(r.lastPush) < r.iv.push {
		return
	}
	r.lastPush = time.Now()
	data, err := os.ReadFile(r.chain.path)
	if err == nil {
		err = r.github.upload(data, fmt.Sprintf("Log entries 0-%d", seq))
	}
	if err != nil {
		fmt.Println("  Warning: GitHub upload failed, will try again:", err)
		return
	}
	r.pushedSeq = seq
}

func (r *runner) finish(con *console, fast bool) error {
	if fast {
		return r.logEntry(&Entry{Type: "session_end", Note: "window closed or computer shutting down"}, false)
	}
	fmt.Println("\nEnding the session...")
	if changes, err := r.watcher.fullCheck(r.chain.files); err == nil {
		if err := r.logChanges(changes, false); err != nil {
			return err
		}
	}
	if err := r.logEntry(&Entry{Type: "session_end"}, true); err != nil {
		return err
	}
	r.maybeAnchor(true)
	r.maybePush(true)
	fmt.Printf("Session ended. The log has %d entries; the fingerprint of the last one is\n  %s\n",
		r.chain.nextSeq, entryHash(r.chain.lastLine))

	if r.settings.ZenodoEnabled && !con.closed && *r.cfg.zenodoToken(r.settings.ZenodoSandbox) != "" {
		site := "Zenodo"
		if r.settings.ZenodoSandbox {
			site = "the Zenodo test site"
		}
		if con.yes(fmt.Sprintf("\nPublish this log as a new version on %s? This creates a permanent public record. [y/N] ", site), false) {
			r.publishZenodo()
		}
	}
	return nil
}

func (r *runner) publishZenodo() {
	data, err := os.ReadFile(r.chain.path)
	if err != nil {
		fmt.Println("Could not read the log:", err)
		return
	}
	var first, last Entry
	readFirstLast(data, &first, &last)
	desc := fmt.Sprintf("Tamper-evident log of the files in the folder %q, written by %s %s. "+
		"It contains %d entries, from %s to %s. See README.txt for how the log is built and checked.",
		filepath.Base(r.folder), toolName, toolVersion, r.chain.nextSeq, first.LocalTime, last.LocalTime)
	meta := map[string]any{
		"title":            "File provenance log: " + filepath.Base(r.folder),
		"upload_type":      "dataset",
		"description":      desc,
		"creators":         []map[string]string{{"name": r.settings.Name, "orcid": r.settings.ORCID}},
		"access_right":     "open",
		"license":          "cc-by-4.0",
		"publication_date": today(),
	}
	z := &zenodoClient{base: zenodoBase(r.settings.ZenodoSandbox), token: *r.cfg.zenodoToken(r.settings.ZenodoSandbox)}
	save := func() error { return writeJSON(settingsPath(r.prov), r.settings, 0o644) }
	fmt.Println("Uploading to Zenodo...")
	dep, err := z.publish(r.settings, save, map[string][]byte{chainName: data, "README.txt": []byte(readmeText)}, meta)
	if err != nil {
		fmt.Println("Zenodo publication failed:", err)
		fmt.Println("Nothing is lost; you will be asked again at the end of the next session.")
		return
	}
	fmt.Println("Published. DOI of this version:", dep.DOI)
	fmt.Println("DOI of all versions together:  ", dep.ConceptDOI)
}

func readFirstLast(data []byte, first, last *Entry) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 {
		return
	}
	jsonUnmarshalString(lines[0], first)
	jsonUnmarshalString(lines[len(lines)-1], last)
}
