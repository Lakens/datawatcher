package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// userConfig is stored in the user's own settings folder, never inside the
// watched folder, because the watched folder may be shared and the tokens
// give write access to the user's GitHub and Zenodo accounts.
type userConfig struct {
	LastFolder         string `json:"last_folder,omitempty"`
	GitHubToken        string `json:"github_token,omitempty"`
	ZenodoToken        string `json:"zenodo_token,omitempty"`
	ZenodoSandboxToken string `json:"zenodo_sandbox_token,omitempty"`
}

// folderSettings is stored in the .provenance folder and holds no secrets.
type folderSettings struct {
	ORCID            string `json:"orcid"`
	Name             string `json:"name"`
	GitHubRepo       string `json:"github_repo,omitempty"`
	GitHubPath       string `json:"github_path,omitempty"`
	ZenodoEnabled    bool   `json:"zenodo_enabled,omitempty"`
	ZenodoSandbox    bool   `json:"zenodo_sandbox,omitempty"`
	ZenodoLatestID   int    `json:"zenodo_latest_id,omitempty"`
	ZenodoDraftID    int    `json:"zenodo_draft_id,omitempty"`
	ZenodoConceptDOI string `json:"zenodo_concept_doi,omitempty"`
}

func (c *userConfig) zenodoToken(sandbox bool) *string {
	if sandbox {
		return &c.ZenodoSandboxToken
	}
	return &c.ZenodoToken
}

func userConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, toolName, "config.json"), nil
}

func readJSON(path string, out any) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(data, out)
}

func writeJSON(path string, v any, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadUserConfig() (*userConfig, error) {
	c := &userConfig{}
	p, err := userConfigPath()
	if err != nil {
		return nil, err
	}
	_, err = readJSON(p, c)
	return c, err
}

func saveUserConfig(c *userConfig) error {
	p, err := userConfigPath()
	if err != nil {
		return err
	}
	return writeJSON(p, c, 0o600)
}

func settingsPath(provDir string) string { return filepath.Join(provDir, "settings.json") }

func loadFolderSettings(provDir string) (*folderSettings, error) {
	s := &folderSettings{}
	found, err := readJSON(settingsPath(provDir), s)
	if err != nil || !found {
		return nil, err
	}
	return s, nil
}
