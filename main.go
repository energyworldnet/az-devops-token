// Command az-devops-token prints a Microsoft Entra access token for the internal
// Azure DevOps Artifacts feeds (usable as an npm _authToken or a NuGet feed
// password).
//
// It authenticates as the signed-in user through a registered Entra public
// client, requesting only the delegated `vso.packaging` (Packaging read) scope —
// so the issued token is limited to reading feeds, not the full-privilege
// `user_impersonation` scope that `az account get-access-token` would return.
//
// Sign in once with `az-devops-token login`, which opens the system browser for
// an interactive sign-in. The refresh token is cached by MSAL; subsequent
// invocations acquire an access token silently. The default (no-argument)
// invocation always exits 0: a missing or expired login must not hard-error
// mise's config load, so on failure it prints nothing and consumers degrade to a
// clean 401.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// adoResource is the public, global Azure DevOps resource ID (identical for
// every tenant — not a secret). The requested scope narrows the token to feed
// reads.
const adoResource = "499b84ac-1321-427f-aa17-267ca6975798"

// clientID and tenantID identify the Entra public-client app registration. They
// are injected at release time via `-ldflags -X`, falling back to the
// AZURE_CLIENT_ID / AZURE_TENANT_ID environment variables for local builds.
// Neither is a secret: a public client has no client secret, and a token still
// requires the user to complete an interactive sign-in against the tenant.
var (
	clientID string
	tenantID string
)

func scopes() []string { return []string{adoResource + "/vso.packaging"} }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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

// fileCache persists MSAL's token cache (which holds the refresh token and any
// live access token) to disk so a single `login` survives across invocations.
type fileCache struct{ path string }

func (c *fileCache) Replace(_ context.Context, u cache.Unmarshaler, _ cache.ReplaceHints) error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		// A missing cache is the normal pre-login state, not an error.
		return nil
	}
	return u.Unmarshal(data)
}

// Export writes atomically (temp + rename, 0600) so concurrent shim invocations
// never read a half-written cache.
func (c *fileCache) Export(_ context.Context, m cache.Marshaler, _ cache.ExportHints) error {
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", c.path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func newApp() (public.Client, error) {
	cid := firstNonEmpty(clientID, os.Getenv("AZURE_CLIENT_ID"))
	tid := firstNonEmpty(tenantID, os.Getenv("AZURE_TENANT_ID"))
	if cid == "" || tid == "" {
		return public.Client{}, fmt.Errorf("client/tenant ID not configured (set AZURE_CLIENT_ID and AZURE_TENANT_ID)")
	}
	return public.New(cid,
		public.WithAuthority("https://login.microsoftonline.com/"+tid),
		public.WithCache(&fileCache{path: cachePath()}),
	)
}

// silentToken returns a cached or silently-refreshed access token, if the user
// has a prior login that is still valid or refreshable.
func silentToken(ctx context.Context, app public.Client) (string, bool) {
	accounts, err := app.Accounts(ctx)
	if err != nil || len(accounts) == 0 {
		return "", false
	}
	res, err := app.AcquireTokenSilent(ctx, scopes(), public.WithSilentAccount(accounts[0]))
	if err != nil {
		return "", false
	}
	return res.AccessToken, true
}

// interactiveLogin opens the system browser for sign-in. Unlike the device-code
// flow, a browser sign-in carries the machine's Entra device identity via SSO, so
// it satisfies Conditional Access policies that require a registered/compliant
// device.
func interactiveLogin(ctx context.Context, app public.Client) error {
	_, err := app.AcquireTokenInteractive(ctx, scopes())
	return err
}

func main() {
	login := len(os.Args) > 1 && os.Args[1] == "login"

	app, err := newApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		if login {
			os.Exit(1)
		}
		return
	}

	// A cached/refreshable token satisfies both paths: it's what `print` emits,
	// and it makes `login` idempotent (no prompt when already signed in).
	silentCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	tok, ok := silentToken(silentCtx, app)
	cancel()
	if ok {
		if login {
			fmt.Fprintln(os.Stderr, "already signed in")
			return
		}
		fmt.Print(tok)
		return
	}

	if !login {
		// No usable token — degrade to empty output so mise's config load and the
		// consuming package manager fall through to a clean 401 rather than erroring.
		fmt.Fprintln(os.Stderr, "no token — run `az-devops-token login`")
		return
	}

	if err := interactiveLogin(context.Background(), app); err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "signed in")
}
