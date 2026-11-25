package main

import (
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

func TestCommandHelp(t *testing.T) {
	for _, cmd := range []string{"show", "verify", "migrate", "export", "import", "grep"} {
		if line := commandHelp(cmd); !strings.HasPrefix(line, cmd) {
			t.Fatalf("%s: unexpected help line %q", cmd, line)
		}
	}
	if commandHelp("remove") != commandHelp("rm") || commandHelp("rm") == "" {
		t.Fatal("alias remove does not resolve to rm")
	}
	if commandHelp("nonexistent") != "" {
		t.Fatal("unknown command returned a help line")
	}
	// "ls" must not match the "ls [filter]" prefix of another command
	if got := commandHelp("l"); got != "" {
		t.Fatalf("partial name matched: %q", got)
	}
}
