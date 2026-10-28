package main

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"
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
		{[]string{"--help"}, 0, usage, ""},
		{[]string{"--version"}, 2, "", "az-devops-token: unknown argument \"--version\"\n\n" + usage},
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
		{[]string{"status", "extra"}, usageErrCmd{reason: `unexpected argument "extra" after status`}},
		{[]string{"help"}, helpCmd{}},
		{[]string{"-h"}, helpCmd{}},
		{[]string{"--help"}, helpCmd{}},
		{[]string{"-help"}, helpCmd{}},
		{[]string{"--version"}, usageErrCmd{reason: `unknown argument "--version"`}},
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
