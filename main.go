package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// console reads typed lines in the background, so that the main loop can
// watch the folder and listen for "stop" at the same time.
type console struct {
	lines  chan string
	closed bool
}

func newConsole() *console {
	c := &console{lines: make(chan string)}
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		close(c.lines)
	}()
	return c
}

func (c *console) ask(prompt string) string {
	fmt.Print(prompt)
	if c.closed {
		fmt.Println()
		return ""
	}
	line, ok := <-c.lines
	if !ok {
		c.closed = true
		fmt.Println()
		return ""
	}
	return strings.TrimSpace(line)
}

func (c *console) yes(prompt string, def bool) bool {
	switch strings.ToLower(c.ask(prompt)) {
	case "":
		return def
	case "y", "yes", "j", "ja":
		return true
	}
	return false
}

func main() {
	reconfigure := flag.Bool("setup", false, "ask the setup questions again for this folder")
	anchorEvery := flag.Duration("anchor-every", 5*time.Minute, "how often to obtain timestamp receipts while there are new entries")
	pushEvery := flag.Duration("push-every", 30*time.Second, "how often to upload the log to GitHub while there are new entries")
	otsEvery := flag.Duration("ots-every", time.Hour, "how often to send the log's fingerprint to OpenTimestamps while there are new entries")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [folder]\n\nWatches a folder and keeps a tamper-evident log of every file version.\n\nOptions:\n", toolName)
		flag.PrintDefaults()
	}
	flag.Parse()

	con := newConsole()
	fmt.Printf("%s %s\n\n", toolName, toolVersion)
	err := run(con, flag.Arg(0), *reconfigure, intervals{*anchorEvery, *pushEvery, *otsEvery})
	if err != nil {
		fmt.Println("\nError:", err)
	}
	if !con.closed {
		// Keep the window open when the program was started by double-clicking.
		con.ask("\nPress Enter to close this window.")
	}
	if err != nil {
		os.Exit(1)
	}
}

type intervals struct {
	anchor, push, ots time.Duration
}

func run(con *console, folderArg string, reconfigure bool, iv intervals) error {
	cfg, err := loadUserConfig()
	if err != nil {
		return fmt.Errorf("could not read your settings: %w", err)
	}
	folder, err := chooseFolder(con, cfg, folderArg)
	if err != nil {
		return err
	}
	prov := filepath.Join(folder, provDirName)
	if err := os.MkdirAll(prov, 0o755); err != nil {
		return err
	}
	chain, err := loadChain(filepath.Join(prov, chainName))
	if err != nil {
		return fmt.Errorf("the existing log could not be used: %w", err)
	}
	st, err := loadFolderSettings(prov)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", settingsPath(prov), err)
	}
	if st == nil || reconfigure {
		if st, err = setupFolder(con, cfg, folder, st, chain.firstHash); err != nil {
			return err
		}
		if err := writeJSON(settingsPath(prov), st, 0o644); err != nil {
			return err
		}
	} else {
		// Tokens are stored per computer. A folder copied from another
		// computer has its settings but not the tokens, so ask for them
		// rather than silently not uploading.
		askMissingTokens(con, cfg, st)
	}
	cfg.LastFolder = folder
	if err := saveUserConfig(cfg); err != nil {
		return fmt.Errorf("could not save your settings: %w", err)
	}
	r, err := newRunner(folder, prov, chain, st, cfg, iv)
	if err != nil {
		return err
	}
	return r.runSession(con)
}

// cleanPath removes the quotes and escapes that a terminal adds when a
// folder is dragged into the window.
func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	if runtime.GOOS != "windows" {
		s = strings.ReplaceAll(s, `\ `, " ")
	}
	if strings.HasPrefix(s, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			s = filepath.Join(home, s[2:])
		}
	}
	return s
}

func chooseFolder(con *console, cfg *userConfig, arg string) (string, error) {
	folder := cleanPath(arg)
	if folder == "" && cfg.LastFolder != "" {
		// The folder from last time is never re-created: a missing folder
		// usually means it was moved or renamed, and re-creating it would
		// start a new log that is not named in the preregistration.
		if info, err := os.Stat(cfg.LastFolder); err != nil || !info.IsDir() {
			fmt.Printf("The folder you watched last time, %s, no longer exists.\n", cfg.LastFolder)
			fmt.Println("If it was moved or renamed, give its new location.")
		} else if con.yes(fmt.Sprintf("Watch %s again? [Y/n] ", cfg.LastFolder), true) {
			folder = cfg.LastFolder
		}
	}
	for {
		if folder == "" {
			folder = cleanPath(con.ask("Folder to watch (you can drag the folder into this window, then press Enter): "))
			if folder == "" {
				if con.closed {
					return "", errors.New("no folder was given")
				}
				continue // an empty answer is not the current folder
			}
		}
		abs, err := filepath.Abs(folder)
		if err != nil {
			fmt.Printf("%q is not a usable folder name.\n", folder)
		} else if info, err := os.Stat(abs); err == nil && info.IsDir() {
			return abs, nil
		} else if err == nil {
			fmt.Printf("%s is a file, not a folder.\n", abs)
		} else if errors.Is(err, fs.ErrNotExist) {
			// Show the full path, because a bare name would be created in
			// whatever folder the program happens to be started from.
			if !con.closed {
				create := con.yes(fmt.Sprintf("The folder %s does not exist. Create it? [Y/n] ", abs), true)
				if create && !con.closed {
					if err := os.MkdirAll(abs, 0o755); err != nil {
						fmt.Println("The folder could not be created:", err)
					} else {
						fmt.Println("Created", abs)
						return abs, nil
					}
				}
			} else {
				fmt.Printf("The folder %s does not exist.\n", abs)
			}
		} else {
			fmt.Printf("%s cannot be opened: %v\n", abs, err)
		}
		if con.closed {
			return "", errors.New("no usable folder was given")
		}
		folder = ""
	}
}

func defaultGitHubPath(folder, firstHash string) string {
	return filepath.Base(folder) + "-" + firstHash[:8] + "/" + chainName
}

// readGitHubToken asks for a token until one works for repo. It returns
// false when nothing is entered.
func readGitHubToken(con *console, cfg *userConfig, repo string) bool {
	fmt.Println("Create a fine-grained token at https://github.com/settings/personal-access-tokens/new")
	fmt.Println("with access to only this repository and the permission Contents: Read and write.")
	for {
		tok := con.ask("Token (stored in your user settings folder, not in the watched folder; press Enter to skip): ")
		if tok == "" {
			return false
		}
		if err := (&githubClient{token: tok, repo: repo}).check(); err != nil {
			fmt.Println("That did not work:", err)
			continue
		}
		cfg.GitHubToken = tok
		return true
	}
}

// readZenodoToken asks for a token until one works. It returns false when
// nothing is entered.
func readZenodoToken(con *console, cfg *userConfig, sandbox bool) bool {
	fmt.Printf("Create a token at %s/account/settings/applications/tokens/new/\n", zenodoBase(sandbox))
	fmt.Println("with the scopes deposit:write and deposit:actions.")
	for {
		tok := con.ask("Token (stored in your user settings folder; press Enter to skip): ")
		if tok == "" {
			return false
		}
		if err := (&zenodoClient{base: zenodoBase(sandbox), token: tok}).check(); err != nil {
			fmt.Println("That did not work:", err)
			continue
		}
		*cfg.zenodoToken(sandbox) = tok
		return true
	}
}

// askMissingTokens asks for tokens that the folder's settings need but that
// are not stored on this computer, for example after the folder was moved
// from another computer.
func askMissingTokens(con *console, cfg *userConfig, st *folderSettings) {
	if st.GitHubRepo != "" && cfg.GitHubToken == "" {
		fmt.Printf("This folder's log is uploaded to the GitHub repository %s,\n", st.GitHubRepo)
		fmt.Println("but no GitHub token is stored on this computer (tokens are stored per computer).")
		if !readGitHubToken(con, cfg, st.GitHubRepo) {
			fmt.Println("Without a token the log will NOT be uploaded to GitHub in this session.")
		}
		fmt.Println()
	}
	if st.ZenodoEnabled && *cfg.zenodoToken(st.ZenodoSandbox) == "" {
		fmt.Println("This folder's log is published on Zenodo, but no Zenodo token is stored on this computer.")
		if !readZenodoToken(con, cfg, st.ZenodoSandbox) {
			fmt.Println("Without a token you will not be offered Zenodo publication in this session.")
		}
		fmt.Println()
	}
}

func setupFolder(con *console, cfg *userConfig, folder string, old *folderSettings, firstHash string) (*folderSettings, error) {
	st := &folderSettings{}
	if old != nil {
		*st = *old
	}
	fmt.Printf("Setting up %s\n\n", folder)

	for {
		hint := ""
		if st.ORCID != "" {
			hint = " [" + st.ORCID + "]"
		}
		in := con.ask("Your ORCID iD, for example 0000-0002-0247-239X" + hint + ": ")
		if in == "" && st.ORCID != "" {
			break
		}
		if con.closed {
			return nil, errors.New("no ORCID iD was given")
		}
		id, ok := normalizeORCID(in)
		if !ok {
			fmt.Println("That is not a valid ORCID iD. Please check the digits.")
			continue
		}
		name, err := fetchORCIDName(id)
		if err != nil || name == "" {
			fmt.Println("The public name on this ORCID record could not be read.")
			name = con.ask("Your name as \"Family name, Given names\": ")
		} else if !con.yes(fmt.Sprintf("This ORCID record belongs to %s. Is that you? [Y/n] ", name), true) {
			continue
		}
		st.ORCID, st.Name = id, name
		break
	}

	fmt.Println("\nGitHub: the log can be copied to a GitHub repository every 30 seconds.")
	fmt.Println("Each copy becomes a public, dated commit.")
	for {
		hint := "press Enter to skip"
		if st.GitHubRepo != "" {
			hint = "press Enter to keep " + st.GitHubRepo + ", or type none to stop using GitHub"
		}
		repo := con.ask("Repository as owner/name (" + hint + "): ")
		if strings.EqualFold(repo, "none") {
			st.GitHubRepo = ""
			break
		}
		if repo == "" {
			repo = st.GitHubRepo
		}
		if repo == "" {
			break
		}
		repo = strings.TrimSuffix(strings.TrimPrefix(repo, "https://github.com/"), ".git")
		if strings.Count(repo, "/") != 1 {
			fmt.Println("Please type the repository as owner/name, for example lakens/my-study-log.")
			continue
		}
		useStored := cfg.GitHubToken != "" && con.yes("Use the GitHub token you entered before? [Y/n] ", true)
		if useStored {
			if err := (&githubClient{token: cfg.GitHubToken, repo: repo}).check(); err != nil {
				fmt.Println("That did not work:", err)
				useStored = false
			}
		}
		if !useStored && !readGitHubToken(con, cfg, repo) {
			if con.closed {
				return nil, errors.New("no working GitHub token was given")
			}
			fmt.Println("Type the repository again, or type none to not use GitHub.")
			continue
		}
		st.GitHubRepo = repo
		// By default the log goes in a folder named after the watched folder
		// and the start of the log's fingerprint, so that logs from several
		// computers can never overwrite each other in one repository.
		def, shown := st.GitHubPath, st.GitHubPath
		if def == "" {
			if firstHash != "" {
				def = defaultGitHubPath(folder, firstHash)
				shown = def
			} else {
				shown = filepath.Base(folder) + "-<first 8 characters of the log's fingerprint>/" + chainName
			}
		}
		if p := con.ask("Where in the repository should the log go? [" + shown + "] "); p != "" {
			def = strings.Trim(filepath.ToSlash(p), "/")
		}
		st.GitHubPath = def // empty until the log exists; filled in when it is created
		break
	}

	fmt.Println("\nZenodo: at the end of each session you can publish the log as a new version")
	fmt.Println("of one Zenodo record. Every version gets a permanent DOI and cannot be deleted.")
	st.ZenodoEnabled = con.yes(fmt.Sprintf("Offer to publish to Zenodo at the end of each session? [%s] ", yn(st.ZenodoEnabled)), st.ZenodoEnabled)
	if st.ZenodoEnabled {
		sandbox := con.yes(fmt.Sprintf("Use the Zenodo test site (sandbox.zenodo.org) instead of the real one? [%s] ", yn(st.ZenodoSandbox)), st.ZenodoSandbox)
		if sandbox != st.ZenodoSandbox {
			st.ZenodoLatestID, st.ZenodoDraftID, st.ZenodoConceptDOI = 0, 0, ""
		}
		st.ZenodoSandbox = sandbox
		tok := cfg.zenodoToken(sandbox)
		useStored := *tok != "" && con.yes("Use the Zenodo token you entered before? [Y/n] ", true)
		if useStored {
			if err := (&zenodoClient{base: zenodoBase(sandbox), token: *tok}).check(); err != nil {
				fmt.Println("That did not work:", err)
				useStored = false
			}
		}
		if !useStored && !readZenodoToken(con, cfg, sandbox) {
			fmt.Println("Zenodo publishing is turned off. Run the program with -setup to turn it on later.")
			st.ZenodoEnabled = false
		}
	}
	fmt.Println()
	return st, nil
}

func yn(def bool) string {
	if def {
		return "Y/n"
	}
	return "y/N"
}
