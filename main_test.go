package main

import (
	"reflect"
	"testing"
)

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
