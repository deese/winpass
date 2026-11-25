package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestWantsHelp(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--help"}, true},
		{[]string{"-h"}, true},
		{[]string{"file.wpx", "--help"}, true},
		{[]string{"--help", "file.wpx"}, true},
		{[]string{"--", "--help"}, false},
		{[]string{"-c", "name"}, false},
	}
	for _, c := range cases {
		if got := wantsHelp(c.args); got != c.want {
			t.Fatalf("%v: got %v, want %v", c.args, got, c.want)
		}
	}
}

// The help must list every mode that migrate --to accepts.
func TestMigrateHelpListsAllModes(t *testing.T) {
	lines := commandHelp("migrate")
	if len(lines) != 1 {
		t.Fatalf("migrate help lines: %q", lines)
	}
	for name := range modeNames {
		if !strings.Contains(lines[0], name) {
			t.Fatalf("migrate help does not mention mode %q: %s", name, lines[0])
		}
	}
}

func TestCommandHelp(t *testing.T) {
	for _, cmd := range []string{"show", "verify", "migrate", "export", "import", "grep", "status"} {
		lines := commandHelp(cmd)
		if len(lines) != 1 || !strings.HasPrefix(lines[0], cmd) {
			t.Fatalf("%s: unexpected help lines %q", cmd, lines)
		}
	}
	if len(commandHelp("setup")) != 2 {
		t.Fatalf("setup should list keyfile and tpm: %q", commandHelp("setup"))
	}
	if !reflect.DeepEqual(commandHelp("remove"), commandHelp("rm")) || len(commandHelp("rm")) != 1 {
		t.Fatal("alias remove does not resolve to rm")
	}
	if len(commandHelp("nonexistent")) != 0 {
		t.Fatal("unknown command returned help lines")
	}
	// Partial names must not match
	if got := commandHelp("l"); len(got) != 0 {
		t.Fatalf("partial name matched: %q", got)
	}
}
