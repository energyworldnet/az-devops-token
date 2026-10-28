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
	"fmt"
	"io"
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
	helpCmd     struct{}
	usageErrCmd struct{ reason string }
)

func (printCmd) isCommand()    {}
func (loginCmd) isCommand()    {}
func (statusCmd) isCommand()   {}
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

// silentSession builds the MSAL client and tries to acquire a token without
// user interaction. A cached/refreshable token satisfies both commands: it's
// what `print` emits, and it makes `login` idempotent (no prompt when already
// signed in).
func silentSession() (app public.Client, res public.AuthResult, ok bool, err error) {
	fc := &token.FileCache{Path: cachePath()}
	app, err = newApp(fc)
	if err != nil {
		return public.Client{}, public.AuthResult{}, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, ok = token.Silent(ctx, app, fc)
	return app, res, ok, nil
}

// actions are the commands that need MSAL and the network, passed to run as
// functions so its dispatch can be tested without either.
type actions struct {
	printToken func(stdout, stderr io.Writer) int
	login      func(stderr io.Writer) int
	status     func(stdout, stderr io.Writer) int
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
			_, res, ok, err := silentSession()
			switch {
			case err != nil:
				fmt.Fprintf(stderr, "%v\n", err)
			case ok:
				fmt.Fprint(stdout, res.AccessToken)
			default:
				// No usable token — degrade to empty output so mise's config load and the
				// consuming package manager fall through to a clean 401 rather than erroring.
				fmt.Fprintln(stderr, "no token — run `az-devops-token login`")
			}
			return 0
		},
		login: func(stderr io.Writer) int {
			app, _, ok, err := silentSession()
			if err != nil {
				fmt.Fprintf(stderr, "%v\n", err)
				return 1
			}
			if ok {
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
			_, res, ok, err := silentSession()
			switch {
			case err != nil:
				fmt.Fprintf(stderr, "%v\n", err)
				return 1
			case !ok:
				fmt.Fprintf(stderr, "not signed in — run `az-devops-token login`\ncache %s\n", cachePath())
				return 1
			}
			fmt.Fprint(stdout, formatStatus(res.Account.PreferredUsername, res.ExpiresOn, time.Now(), cachePath()))
			return 0
		},
	}
}

// run executes the command the arguments select and returns the exit code.
func run(args []string, stdout, stderr io.Writer, act actions) int {
	switch cmd := parseCommand(args).(type) {
	case helpCmd:
		fmt.Fprint(stdout, usage)
		return 0
	case usageErrCmd:
		fmt.Fprintf(stderr, "az-devops-token: %s\n\n%s", cmd.reason, usage)
		return 2
	case loginCmd:
		return act.login(stderr)
	case statusCmd:
		return act.status(stdout, stderr)
	case printCmd:
		return act.printToken(stdout, stderr)
	default:
		panic(fmt.Sprintf("unhandled command %T", cmd))
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, msalActions()))
}
