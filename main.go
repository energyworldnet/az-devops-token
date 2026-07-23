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
//
// Token acquisition, the minimum-lifetime guarantee, and the on-disk cache live
// in internal/token; this file is the CLI wiring.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/energyworldnet/az-devops-token/internal/token"
)

// clientID and tenantID identify the Entra public-client app registration. They
// are injected at release time via `-ldflags -X`, falling back to the
// AZURE_CLIENT_ID / AZURE_TENANT_ID environment variables for local builds.
// Neither is a secret: a public client has no client secret, and a token still
// requires the user to complete an interactive sign-in against the tenant.
var (
	clientID string
	tenantID string
)

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

func newApp(fc *token.FileCache) (public.Client, error) {
	cid := firstNonEmpty(clientID, os.Getenv("AZURE_CLIENT_ID"))
	tid := firstNonEmpty(tenantID, os.Getenv("AZURE_TENANT_ID"))
	if cid == "" || tid == "" {
		return public.Client{}, fmt.Errorf("client/tenant ID not configured (set AZURE_CLIENT_ID and AZURE_TENANT_ID)")
	}
	return public.New(cid,
		public.WithAuthority("https://login.microsoftonline.com/"+tid),
		public.WithCache(fc),
	)
}

// interactiveLogin opens the system browser for sign-in. Unlike the device-code
// flow, a browser sign-in carries the machine's Entra device identity via SSO, so
// it satisfies Conditional Access policies that require a registered/compliant
// device.
func interactiveLogin(ctx context.Context, app public.Client) error {
	_, err := app.AcquireTokenInteractive(ctx, token.Scopes())
	return err
}

func main() {
	login := len(os.Args) > 1 && os.Args[1] == "login"

	fc := &token.FileCache{Path: cachePath()}
	app, err := newApp(fc)
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
	tok, ok := token.Silent(silentCtx, app, fc)
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
