// Command az-devops-token authenticates the internal Azure DevOps Artifacts
// feeds via a Microsoft Entra access token.
//
// With no arguments it prints a cached token (usable as an npm _authToken or a
// NuGet feed password), shelling out to the Azure CLI so the login session and
// refresh token stay in az's store — it only caches the short-lived access
// token, to avoid az's startup cost on every mise `[env]` evaluation. In that
// mode it always exits 0: a missing or unauthenticated az must not hard-error
// mise's config load, so on failure it prints nothing and consumers get a
// clean 401.
//
// The `login` subcommand ensures an az session (interactive if needed) and is
// meant for a one-time setup step — where `[env]` can't run, since it must stay
// silent and non-interactive on every shimmed command.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

// azCmd builds an `az <args...>` invocation. On Windows the mise pipx install of
// azure-cli ships an `az.bat` wrapper that can't find its venv Python under uv's
// layout, so call that Python's azure.cli module directly (bypassing the broken
// wrapper). Everywhere else, `az` works as-is.
func azCmd(args ...string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		if py := azureCliPython(); py != "" {
			return exec.Command(py, append([]string{"-m", "azure.cli"}, args...)...)
		}
	}
	return exec.Command("az", args...)
}

// azureCliPython locates azure-cli's venv Python via mise. `--no-env` skips
// re-evaluating `[env]`, which would recurse back into this binary.
func azureCliPython() string {
	out, err := exec.Command("mise", "--no-env", "where", "pipx:azure-cli").Output()
	if err != nil {
		return ""
	}
	py := filepath.Join(strings.TrimSpace(string(out)), "azure-cli", "Scripts", "python.exe")
	if _, err := os.Stat(py); err != nil {
		return ""
	}
	return py
}

func fromAz() (token, bool) {
	out, err := azCmd("account", "get-access-token", "--resource", adoResource, "--output", "json").Output()
	if err != nil {
		return token{}, false
	}
	var raw struct {
		AccessToken string `json:"accessToken"`
		ExpiresOn   int64  `json:"expires_on"` // unix seconds; falls back below if absent
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

// login ensures an az session that can mint feed tokens, prompting
// interactively only when one isn't already present. Intended for a one-time
// setup step. The "signed in?" check tests token acquisition directly, which
// is more precise than `az account show` for accounts without a subscription.
func login() int {
	if azCmd("account", "get-access-token", "--resource", adoResource).Run() == nil {
		return 0 // already able to get a token
	}
	// --allow-no-subscriptions: EWN accounts commonly have Azure DevOps access
	// without an Azure subscription, which a plain `az login` rejects.
	c := azCmd("login", "--allow-no-subscriptions")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "az-devops-token: login failed: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "login" {
		os.Exit(login())
	}

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
	fmt.Fprintln(os.Stderr, "az-devops-token: no token — run `az-devops-token login`")
}
