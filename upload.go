package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------- GitHub: a public copy of the log, updated every 30 seconds ----------

const githubAPI = "https://api.github.com"

type githubClient struct {
	token string
	repo  string // owner/name
	path  string // path of the log inside the repository
	sha   string // GitHub's identifier of the current version of that file
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func (g *githubClient) request(method, u, accept string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", userAgent)
	resp, err := uploadClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		json.Unmarshal(data, &e)
		return resp.StatusCode, fmt.Errorf("GitHub answered with status %d: %s", resp.StatusCode, e.Message)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// check confirms that the repository exists and the token can reach it.
func (g *githubClient) check() error {
	code, err := g.request("GET", githubAPI+"/repos/"+g.repo, "application/vnd.github+json", nil, nil)
	switch {
	case code == 401:
		return fmt.Errorf("GitHub did not accept the token")
	case code == 404:
		return fmt.Errorf("the repository %s does not exist, or the token has no access to it", g.repo)
	}
	return err
}

// refresh looks up the current version of the log file in the repository.
func (g *githubClient) refresh() error {
	var r struct {
		SHA string `json:"sha"`
	}
	u := githubAPI + "/repos/" + g.repo + "/contents/" + escapePath(g.path)
	code, err := g.request("GET", u, "application/vnd.github.object", nil, &r)
	if code == 404 {
		g.sha = ""
		return nil
	}
	if err != nil {
		return err
	}
	g.sha = r.SHA
	return nil
}

// upload replaces the log file in the repository with content; each upload
// becomes one commit, dated by GitHub.
func (g *githubClient) upload(content []byte, message string) error {
	put := func() (int, error) {
		body := map[string]string{
			"message": message,
			"content": base64.StdEncoding.EncodeToString(content),
		}
		if g.sha != "" {
			body["sha"] = g.sha
		}
		var r struct {
			Content struct {
				SHA string `json:"sha"`
			} `json:"content"`
		}
		u := githubAPI + "/repos/" + g.repo + "/contents/" + escapePath(g.path)
		code, err := g.request("PUT", u, "application/vnd.github+json", body, &r)
		if err == nil {
			g.sha = r.Content.SHA
		}
		return code, err
	}
	code, err := put()
	if code == 409 || code == 422 {
		// The stored version identifier is out of date; look it up and try once more.
		if rerr := g.refresh(); rerr != nil {
			return rerr
		}
		_, err = put()
	}
	return err
}

// ---------- Zenodo: a permanent, citable copy at the end of a session ----------

func zenodoBase(sandbox bool) string {
	if sandbox {
		return "https://sandbox.zenodo.org"
	}
	return "https://zenodo.org"
}

type zenodoClient struct {
	base  string
	token string
}

type zenodoDeposition struct {
	ID         int    `json:"id"`
	DOI        string `json:"doi"`
	ConceptDOI string `json:"conceptdoi"`
	Links      struct {
		Bucket      string `json:"bucket"`
		LatestDraft string `json:"latest_draft"`
		HTML        string `json:"html"`
	} `json:"links"`
}

type zenodoFile struct {
	ID json.RawMessage `json:"id"`
}

func (z *zenodoClient) request(method, u, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+z.token)
	req.Header.Set("User-Agent", userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := uploadClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return fmt.Errorf("Zenodo answered %s %s with status %d: %s", method, u, resp.StatusCode, msg)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (z *zenodoClient) jsonRequest(method, u string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	return z.request(method, u, "application/json", rd, out)
}

func (z *zenodoClient) check() error {
	return z.jsonRequest("GET", z.base+"/api/deposit/depositions?size=1", nil, nil)
}

// publish creates a new version of the study's Zenodo record containing the
// given files. Zenodo gives every version its own permanent DOI, and one
// concept DOI that always points to the newest version.
func (z *zenodoClient) publish(st *folderSettings, save func() error, files map[string][]byte, meta map[string]any) (*zenodoDeposition, error) {
	api := z.base + "/api/deposit/depositions"
	var dep zenodoDeposition
	switch {
	case st.ZenodoDraftID != 0:
		// An earlier attempt created a draft but did not finish; continue it.
		if err := z.jsonRequest("GET", fmt.Sprintf("%s/%d", api, st.ZenodoDraftID), nil, &dep); err != nil {
			return nil, err
		}
	case st.ZenodoLatestID != 0:
		var orig zenodoDeposition
		if err := z.jsonRequest("POST", fmt.Sprintf("%s/%d/actions/newversion", api, st.ZenodoLatestID), nil, &orig); err != nil {
			return nil, err
		}
		if orig.Links.LatestDraft == "" {
			return nil, fmt.Errorf("Zenodo did not return the address of the new version")
		}
		if err := z.jsonRequest("GET", orig.Links.LatestDraft, nil, &dep); err != nil {
			return nil, err
		}
	default:
		if err := z.jsonRequest("POST", api, map[string]any{}, &dep); err != nil {
			return nil, err
		}
	}
	st.ZenodoDraftID = dep.ID
	if err := save(); err != nil {
		return nil, err
	}

	// A new version starts with the previous version's files; remove them.
	var existing []zenodoFile
	if err := z.jsonRequest("GET", fmt.Sprintf("%s/%d/files", api, dep.ID), nil, &existing); err != nil {
		return nil, err
	}
	for _, f := range existing {
		id := strings.Trim(string(f.ID), `"`)
		if err := z.jsonRequest("DELETE", fmt.Sprintf("%s/%d/files/%s", api, dep.ID, url.PathEscape(id)), nil, nil); err != nil {
			return nil, err
		}
	}
	if dep.Links.Bucket == "" {
		return nil, fmt.Errorf("Zenodo did not return an upload address")
	}
	for name, data := range files {
		if err := z.request("PUT", dep.Links.Bucket+"/"+url.PathEscape(name), "application/octet-stream", bytes.NewReader(data), nil); err != nil {
			return nil, err
		}
	}
	if err := z.jsonRequest("PUT", fmt.Sprintf("%s/%d", api, dep.ID), map[string]any{"metadata": meta}, nil); err != nil {
		return nil, err
	}
	var published zenodoDeposition
	if err := z.jsonRequest("POST", fmt.Sprintf("%s/%d/actions/publish", api, dep.ID), nil, &published); err != nil {
		return nil, err
	}
	st.ZenodoLatestID = published.ID
	st.ZenodoConceptDOI = published.ConceptDOI
	st.ZenodoDraftID = 0
	return &published, save()
}

// ---------- ORCID ----------

// normalizeORCID accepts an iD with or without the https://orcid.org/
// prefix and checks its check digit (ISO 7064 11,2).
func normalizeORCID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, p := range []string{"https://orcid.org/", "http://orcid.org/", "orcid.org/"} {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.ToUpper(s)
	if len(s) != 19 || s[4] != '-' || s[9] != '-' || s[14] != '-' {
		return "", false
	}
	digits := strings.ReplaceAll(s, "-", "")
	total := 0
	for i := 0; i < 15; i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return "", false
		}
		total = (total + int(c-'0')) * 2
	}
	result := (12 - total%11) % 11
	want := byte('0' + result)
	if result == 10 {
		want = 'X'
	}
	if digits[15] != want {
		return "", false
	}
	return s, true
}

// fetchORCIDName returns the public name on an ORCID record as
// "Family name, Given names", the form Zenodo asks for.
func fetchORCIDName(id string) (string, error) {
	var r struct {
		Name struct {
			Given struct {
				Value string `json:"value"`
			} `json:"given-names"`
			Family struct {
				Value string `json:"value"`
			} `json:"family-name"`
		} `json:"name"`
	}
	if err := getJSON(httpClient, "https://pub.orcid.org/v3.0/"+id+"/person", &r); err != nil {
		return "", err
	}
	given, family := r.Name.Given.Value, r.Name.Family.Value
	switch {
	case family != "" && given != "":
		return family + ", " + given, nil
	case family != "":
		return family, nil
	}
	return given, nil
}

func today() string { return time.Now().Format("2006-01-02") }
