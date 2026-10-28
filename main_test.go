package main

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
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
	}
}

func TestRun(t *testing.T) {
	cases := []struct {
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{nil, 3, "SECRET", ""},
		{[]string{"print"}, 3, "SECRET", ""},
		{[]string{"login"}, 4, "", "signed in"},
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
		{nil, printCmd{}},
		{[]string{"print"}, printCmd{}},
		{[]string{"print", "--help"}, usageErrCmd{reason: `unexpected argument "--help" after print`}},
		{[]string{"login"}, loginCmd{}},
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
