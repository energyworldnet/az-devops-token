package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/energyworldnet/az-devops-token/internal/token"
)

// fakeActions stands in for MSAL: printToken emits a sentinel token, so a
// dispatch bug that routes to it shows up on stdout. Each action returns its
// own exit code, so a test sees which one ran and that run passes it on.
func fakeActions() actions {
	return actions{
		printToken: func(stdout, _ io.Writer) int {
			fmt.Fprint(stdout, "SECRET")
			return 3
		},
		login: func(stderr io.Writer) int {
			fmt.Fprint(stderr, "signed in")
			return 4
		},
		status: func(stdout, _ io.Writer) int {
			fmt.Fprint(stdout, "STATUS")
			return 5
		},
		logout: func(stdout, _ io.Writer) int {
			fmt.Fprint(stdout, "LOGOUT")
			return 6
		},
	}
}

func TestLogoutReport(t *testing.T) {
	cases := []struct {
		name       string
		removeErr  error
		wantStdout string
		wantStderr string
		wantCode   int
	}{
		{"removed", nil, "signed out\ncache /c.json removed\n", "", 0},
		{"no cache", fmt.Errorf("remove /c.json: %w", fs.ErrNotExist), "already signed out\ncache /c.json\n", "", 0},
		{"remove failed", errors.New("permission denied"), "", "logout failed: permission denied\ncache /c.json\n", 1},
	}
	for _, c := range cases {
		stdout, stderr, code := logoutReport(c.removeErr, "/c.json")
		if stdout != c.wantStdout || stderr != c.wantStderr || code != c.wantCode {
			t.Errorf("%s: logoutReport = %q, %q, %d; want %q, %q, %d",
				c.name, stdout, stderr, code, c.wantStdout, c.wantStderr, c.wantCode)
		}
	}
}

func TestStatusReport(t *testing.T) {
	now := time.Date(2026, 10, 28, 17, 0, 0, 0, time.UTC)
	signedIn := public.AuthResult{
		AccessToken: "SECRET",
		Account:     public.Account{PreferredUsername: "alice@example.com"},
		ExpiresOn:   now.Add(30 * time.Minute),
	}
	cases := []struct {
		name       string
		res        public.AuthResult
		err        error
		wantStdout string
		wantStderr string
		wantCode   int
	}{
		{
			name: "signed in",
			res:  signedIn,
			wantStdout: "signed in as alice@example.com\n" +
				"token expires 2026-10-28T17:30:00Z (in 30m)\n" +
				"cache /c.json\n",
			wantCode: 0,
		},
		{
			name:       "not signed in",
			err:        token.ErrNotSignedIn,
			wantStderr: "not signed in — run `az-devops-token login`\ncache /c.json\n",
			wantCode:   1,
		},
		{
			name: "acquisition failed",
			err:  errors.New("network unreachable"),
			wantStderr: "token acquisition failed: network unreachable\n" +
				"if your sign-in expired, run `az-devops-token login`\n" +
				"cache /c.json\n",
			wantCode: 1,
		},
	}
	for _, c := range cases {
		stdout, stderr, code := statusReport(c.res, c.err, now, "/c.json")
		if stdout != c.wantStdout || stderr != c.wantStderr || code != c.wantCode {
			t.Errorf("%s: statusReport = %q, %q, %d; want %q, %q, %d",
				c.name, stdout, stderr, code, c.wantStdout, c.wantStderr, c.wantCode)
		}
		if strings.Contains(stdout+stderr, "SECRET") {
			t.Errorf("%s: statusReport leaked the access token", c.name)
		}
	}
}

func TestFormatStatus(t *testing.T) {
	now := time.Date(2026, 10, 28, 17, 0, 0, 0, time.UTC)
	cases := []struct {
		expiresOn time.Time
		want      string
	}{
		{
			now.Add(58*time.Minute + 30*time.Second),
			"signed in as alice@example.com\n" +
				"token expires 2026-10-28T17:58:30Z (in 58m)\n" +
				"cache /home/alice/.cache/az-devops-token.json\n",
		},
		{
			now.Add(75 * time.Minute),
			"signed in as alice@example.com\n" +
				"token expires 2026-10-28T18:15:00Z (in 1h15m)\n" +
				"cache /home/alice/.cache/az-devops-token.json\n",
		},
	}
	for _, c := range cases {
		got := formatStatus("alice@example.com", c.expiresOn, now, "/home/alice/.cache/az-devops-token.json")
		if got != c.want {
			t.Errorf("formatStatus(expires %v) = %q, want %q", c.expiresOn, got, c.want)
		}
	}
}

func TestRun(t *testing.T) {
	cases := []struct {
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{nil, 2, "", "az-devops-token: missing command\n\n" + usage},
		{[]string{"print"}, 3, "SECRET", ""},
		{[]string{"login"}, 4, "", "signed in"},
		{[]string{"status"}, 5, "STATUS", ""},
		{[]string{"logout"}, 6, "LOGOUT", ""},
		{[]string{"--help"}, 0, usage, ""},
		{[]string{"version"}, 0, "az-devops-token dev\n", ""},
		{[]string{"--version"}, 0, "az-devops-token dev\n", ""},
		{[]string{"--verbose"}, 2, "", "az-devops-token: unknown argument \"--verbose\"\n\n" + usage},
		{[]string{"print", "extra"}, 2, "", "az-devops-token: unexpected argument \"extra\" after print\n\n" + usage},
	}
	for _, c := range cases {
		var stdout, stderr bytes.Buffer
		code := run(c.args, &stdout, &stderr, fakeActions())
		if code != c.wantCode || stdout.String() != c.wantStdout || stderr.String() != c.wantStderr {
			t.Errorf("run(%q) = %d, stdout %q, stderr %q; want %d, %q, %q",
				c.args, code, stdout.String(), stderr.String(), c.wantCode, c.wantStdout, c.wantStderr)
		}
	}
}

func TestParseCommand(t *testing.T) {
	cases := []struct {
		args []string
		want command
	}{
		{nil, usageErrCmd{reason: "missing command"}},
		{[]string{"print"}, printCmd{}},
		{[]string{"print", "--help"}, usageErrCmd{reason: `unexpected argument "--help" after print`}},
		{[]string{"login"}, loginCmd{}},
		{[]string{"status"}, statusCmd{}},
		{[]string{"logout"}, logoutCmd{}},
		{[]string{"logout", "extra"}, usageErrCmd{reason: `unexpected argument "extra" after logout`}},
		{[]string{"status", "extra"}, usageErrCmd{reason: `unexpected argument "extra" after status`}},
		{[]string{"help"}, helpCmd{}},
		{[]string{"-h"}, helpCmd{}},
		{[]string{"--help"}, helpCmd{}},
		{[]string{"-help"}, helpCmd{}},
		{[]string{"version"}, versionCmd{}},
		{[]string{"--version"}, versionCmd{}},
		{[]string{"version", "extra"}, usageErrCmd{reason: `unexpected argument "extra" after version`}},
		{[]string{"--verbose"}, usageErrCmd{reason: `unknown argument "--verbose"`}},
		{[]string{"get"}, usageErrCmd{reason: `unknown argument "get"`}},
		{[]string{"login", "--help"}, usageErrCmd{reason: `unexpected argument "--help" after login`}},
		{[]string{"--help", "login"}, usageErrCmd{reason: `unexpected argument "login" after --help`}},
	}
	for _, c := range cases {
		if got := parseCommand(c.args); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseCommand(%q) = %#v, want %#v", c.args, got, c.want)
		}
	}
}
