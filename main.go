// Command az-devops-token prints a cached Microsoft Entra access token for the
// internal Azure DevOps Artifacts feeds (usable as an npm _authToken or a NuGet
// feed password).
//
// It shells out to the Azure CLI for the actual authentication, so the login
// session and refresh token stay in az's secure store — this tool only caches
// the short-lived access token, to avoid az's ~660ms startup on every mise
// `[env]` evaluation (which runs on every shimmed command). It always exits 0:
// a missing or unauthenticated az must not hard-error mise's config load, so on
// failure it prints nothing and consumers degrade to a clean 401.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// adoResource is the public, global Azure DevOps resource ID (identical for
// every tenant — not a secret).
const adoResource = "499b84ac-1321-427f-aa17-267ca6975798"

// refreshSkew renews slightly early so a token never expires mid-command.
const refreshSkew = 5 * time.Minute

type token struct {
	AccessToken string `json:"accessToken"`
	Expiry      int64  `json:"expiry"` // unix seconds
}

func cachePath() string {
	if p := os.Getenv("AZ_DEVOPS_TOKEN_CACHE"); p != "" {
		return p
	}
	dir := os.Getenv("XDG_CACHE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "az-devops-token.json")
}

func fromCache(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var t token
	if err := json.Unmarshal(data, &t); err != nil || t.AccessToken == "" {
		return "", false
	}
	if time.Now().Add(refreshSkew).Unix() >= t.Expiry {
		return "", false
	}
	return t.AccessToken, true
}

// fromAz runs `az account get-access-token`. az's JSON carries `expires_on`
// (unix seconds) on current versions; fall back to a conservative TTL if it's
// absent so caching still works on older az.
func fromAz() (token, bool) {
	out, err := exec.Command("az", "account", "get-access-token",
		"--resource", adoResource, "--output", "json").Output()
	if err != nil {
		return token{}, false
	}
	var raw struct {
		AccessToken string `json:"accessToken"`
		ExpiresOn   int64  `json:"expires_on"`
	}
	if err := json.Unmarshal(out, &raw); err != nil || raw.AccessToken == "" {
		return token{}, false
	}
	expiry := raw.ExpiresOn
	if expiry == 0 {
		expiry = time.Now().Add(45 * time.Minute).Unix()
	}
	return token{AccessToken: raw.AccessToken, Expiry: expiry}, true
}

// store writes atomically (temp + rename) so concurrent shim invocations never
// read a half-written token.
func store(path string, t token) {
	data, err := json.Marshal(t)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func main() {
	path := cachePath()
	if tok, ok := fromCache(path); ok {
		fmt.Print(tok)
		return
	}
	if t, ok := fromAz(); ok {
		store(path, t)
		fmt.Print(t.AccessToken)
		return
	}
	fmt.Fprintln(os.Stderr, "az-devops-token: no token — is az installed and logged in?")
}
