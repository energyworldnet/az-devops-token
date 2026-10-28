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
// invocations acquire an access token silently. `az-devops-token print` always
// exits 0: a missing or expired login must not hard-error mise's config load,
// so on failure it prints nothing and consumers degrade to a clean 401.
//
// Token acquisition, the minimum-lifetime guarantee, and the on-disk cache live
// in internal/token; this file is the CLI wiring.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// version is the release tag, injected alongside the app IDs; local builds
// report "dev".
var version = "dev"

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

// command is the invocation selected by the arguments. Only printCmd writes a
// token to stdout.
type command interface{ isCommand() }

type (
	printCmd    struct{}
	loginCmd    struct{}
	statusCmd   struct{}
	logoutCmd   struct{}
	versionCmd  struct{}
	helpCmd     struct{}
	usageErrCmd struct{ reason string }
)

func (printCmd) isCommand()    {}
func (loginCmd) isCommand()    {}
func (statusCmd) isCommand()   {}
func (logoutCmd) isCommand()   {}
func (versionCmd) isCommand()  {}
func (helpCmd) isCommand()     {}
func (usageErrCmd) isCommand() {}

/*
parseCommand maps arguments to a command. Printing a token requires `print`:
anything else, including no arguments, must fail closed, because a caller
probing the CLI would otherwise get a live token on stdout.
*/
func parseCommand(args []string) command {
	if len(args) == 0 {
		return usageErrCmd{reason: "missing command"}
	}
	var cmd command
	switch args[0] {
	case "print":
		cmd = printCmd{}
	case "login":
		cmd = loginCmd{}
	case "status":
		cmd = statusCmd{}
	case "logout":
		cmd = logoutCmd{}
	case "version", "--version":
		cmd = versionCmd{}
	case "help", "-h", "-help", "--help":
		cmd = helpCmd{}
	default:
		return usageErrCmd{reason: fmt.Sprintf("unknown argument %q", args[0])}
	}
	if len(args) > 1 {
		return usageErrCmd{reason: fmt.Sprintf("unexpected argument %q after %s", args[1], args[0])}
	}
	return cmd
}

const usage = `Usage:
  az-devops-token print    print a vso.packaging access token to stdout
  az-devops-token login    sign in interactively (once per machine)
  az-devops-token status   show the signed-in account and token expiry
  az-devops-token logout   delete the cached sign-in
  az-devops-token version  show the release this binary was built from
  az-devops-token --help   show this help
`

// interactiveLogin opens the system browser for sign-in. Unlike the device-code
// flow, a browser sign-in carries the machine's Entra device identity via SSO, so
// it satisfies Conditional Access policies that require a registered/compliant
// device.
func interactiveLogin(ctx context.Context, app public.Client) error {
	_, err := app.AcquireTokenInteractive(ctx, token.Scopes())
	return err
}

// newSession builds the MSAL client over the on-disk cache. Its only failure is
// missing configuration, which no login can fix.
func newSession() (public.Client, *token.FileCache, error) {
	fc := &token.FileCache{Path: cachePath()}
	app, err := newApp(fc)
	return app, fc, err
}

// acquireSilently tries to get a token without user interaction. A
// cached/refreshable token satisfies every command: it's what `print` emits and
// `status` describes, and it makes `login` idempotent (no prompt when already
// signed in).
func acquireSilently(app public.Client, fc *token.FileCache) (public.AuthResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return token.Silent(ctx, app, fc)
}

// actions are the commands that need MSAL and the network, passed to run as
// functions so its dispatch can be tested without either.
type actions struct {
	printToken func(stdout, stderr io.Writer) int
	login      func(stderr io.Writer) int
	status     func(stdout, stderr io.Writer) int
	logout     func(stdout, stderr io.Writer) int
}

/*
logoutReport renders the outcome of deleting the token cache for `logout`. A
cache that is already gone counts as success, so logging out is idempotent.
*/
func logoutReport(removeErr error, cache string) (stdout, stderr string, code int) {
	switch {
	case removeErr == nil:
		return fmt.Sprintf("signed out\ncache %s removed\n", cache), "", 0
	case errors.Is(removeErr, fs.ErrNotExist):
		return fmt.Sprintf("already signed out\ncache %s\n", cache), "", 0
	}
	return "", fmt.Sprintf("logout failed: %v\ncache %s\n", removeErr, cache), 1
}

/*
statusReport renders the outcome of a silent acquisition for `status`. It
receives the whole AuthResult but writes only what formatStatus derives from
it, so the access token reaches neither stream.
*/
func statusReport(res public.AuthResult, err error, now time.Time, cache string) (stdout, stderr string, code int) {
	switch {
	case errors.Is(err, token.ErrNotSignedIn):
		return "", fmt.Sprintf("not signed in — run `az-devops-token login`\ncache %s\n", cache), 1
	case err != nil:
		return "", fmt.Sprintf("token acquisition failed: %v\n"+
			"if your sign-in expired, run `az-devops-token login`\ncache %s\n", err, cache), 1
	}
	return formatStatus(res.Account.PreferredUsername, res.ExpiresOn, now, cache), "", 0
}

/*
formatStatus describes a usable login without the token itself, so checking
that the tool works never puts a credential on screen or in a transcript.
*/
func formatStatus(username string, expiresOn, now time.Time, cache string) string {
	remaining := strings.TrimSuffix(expiresOn.Sub(now).Truncate(time.Minute).String(), "0s")
	return fmt.Sprintf("signed in as %s\ntoken expires %s (in %s)\ncache %s\n",
		username, expiresOn.UTC().Format(time.RFC3339), remaining, cache)
}

func msalActions() actions {
	return actions{
		printToken: func(stdout, stderr io.Writer) int {
			app, fc, err := newSession()
			if err != nil {
				fmt.Fprintf(stderr, "%v\n", err)
				return 0
			}
			res, err := acquireSilently(app, fc)
			switch {
			case err == nil:
				fmt.Fprint(stdout, res.AccessToken)
			case errors.Is(err, token.ErrNotSignedIn):
				// No usable token — degrade to empty output so mise's config load and the
				// consuming package manager fall through to a clean 401 rather than erroring.
				fmt.Fprintln(stderr, "no token — run `az-devops-token login`")
			default:
				fmt.Fprintf(stderr, "no token — %v\n", err)
			}
			return 0
		},
		login: func(stderr io.Writer) int {
			app, fc, err := newSession()
			if err != nil {
				fmt.Fprintf(stderr, "%v\n", err)
				return 1
			}
			if _, err := acquireSilently(app, fc); err == nil {
				fmt.Fprintln(stderr, "already signed in")
				return 0
			}
			if err := interactiveLogin(context.Background(), app); err != nil {
				fmt.Fprintf(stderr, "login failed: %v\n", err)
				return 1
			}
			fmt.Fprintln(stderr, "signed in")
			return 0
		},
		status: func(stdout, stderr io.Writer) int {
			app, fc, err := newSession()
			if err != nil {
				fmt.Fprintf(stderr, "%v\n", err)
				return 1
			}
			res, err := acquireSilently(app, fc)
			out, errOut, code := statusReport(res, err, time.Now(), fc.Path)
			fmt.Fprint(stdout, out)
			fmt.Fprint(stderr, errOut)
			return code
		},
		// logout deletes the whole cache rather than asking MSAL to remove the
		// account, so it drops the refresh token even when the client and tenant
		// IDs are not configured.
		logout: func(stdout, stderr io.Writer) int {
			path := cachePath()
			out, errOut, code := logoutReport(os.Remove(path), path)
			fmt.Fprint(stdout, out)
			fmt.Fprint(stderr, errOut)
			return code
		},
	}
}

// run executes the command the arguments select and returns the exit code.
func run(args []string, stdout, stderr io.Writer, act actions) int {
	switch cmd := parseCommand(args).(type) {
	case helpCmd:
		fmt.Fprint(stdout, usage)
		return 0
	case versionCmd:
		fmt.Fprintf(stdout, "az-devops-token %s\n", version)
		return 0
	case usageErrCmd:
		fmt.Fprintf(stderr, "az-devops-token: %s\n\n%s", cmd.reason, usage)
		return 2
	case loginCmd:
		return act.login(stderr)
	case statusCmd:
		return act.status(stdout, stderr)
	case logoutCmd:
		return act.logout(stdout, stderr)
	case printCmd:
		return act.printToken(stdout, stderr)
	default:
		panic(fmt.Sprintf("unhandled command %T", cmd))
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, msalActions()))
}
