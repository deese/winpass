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

// Every option a command parses must appear in its help, short form and long
// form. The table mirrors the flag specs in the command implementations.
func TestHelpListsAllOptions(t *testing.T) {
	cases := map[string][]string{
		"show":     {"-c", "--clip"},
		"insert":   {"-e", "--echo", "-m", "--multiline", "-f", "--force"},
		"generate": {"-n", "--no-symbols", "-c", "--clip", "-i", "--in-place", "-f", "--force"},
		"rm":       {"-r", "--recursive", "-f", "--force"},
		"mv":       {"-f", "--force"},
		"cp":       {"-f", "--force"},
		"grep":     {"-i", "--ignore-case"},
		"import":   {"-f", "--force"},
		"verify":   {"-c", "--clip"},
		"migrate":  {"--to", "--skip-backup"},
		"setup":    {"--remove", "--force"},
	}
	for cmd, options := range cases {
		help := strings.Join(commandHelp(cmd), "\n")
		for _, opt := range options {
			if !strings.Contains(help, opt) {
				t.Errorf("help for %s does not mention %s:\n%s", cmd, opt, help)
			}
		}
	}
}

func TestUsageAlignsDescriptions(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(buildUsage()), "\n")
	column := -1
	for _, line := range lines[3:] { // skip "Usage", blank and "Commands:"
		rest := strings.TrimPrefix(line, "  ")
		gap := strings.Index(rest, "  ")
		if gap < 0 {
			t.Fatalf("line has no description column: %q", line)
		}
		// the description starts after the padding that follows the syntax
		pos := gap + len(rest[gap:]) - len(strings.TrimLeft(rest[gap:], " "))
		if column == -1 {
			column = pos
		}
		if pos != column {
			t.Fatalf("misaligned line: %q (column %d, want %d)", line, pos, column)
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
	if len(commandHelp("setup")) != 4 {
		t.Fatalf("setup should list create and remove for keyfile and tpm: %q", commandHelp("setup"))
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
