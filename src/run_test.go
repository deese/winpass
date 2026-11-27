package main

import (
	"reflect"
	"slices"
	"testing"
)

func TestParseRunArgs(t *testing.T) {
	bindings, command, err := parseRunArgs([]string{"-e", "A=x/a", "--env", "B=y", "--env=C=z", "-eD=w", "--", "uvx", "ha-mcp@latest", "-e", "keep"})
	if err != nil {
		t.Fatal(err)
	}
	want := []envBinding{{"A", "x/a"}, {"B", "y"}, {"C", "z"}, {"D", "w"}}
	if !reflect.DeepEqual(bindings, want) {
		t.Fatalf("bindings: got %v, want %v", bindings, want)
	}
	if !reflect.DeepEqual(command, []string{"uvx", "ha-mcp@latest", "-e", "keep"}) {
		t.Fatalf("command: got %v", command)
	}
}

func TestParseRunArgsErrors(t *testing.T) {
	cases := map[string][]string{
		"no separator":    {"-e", "A=x"},
		"no command":      {"-e", "A=x", "--"},
		"no binding":      {"--", "cmd"},
		"missing value":   {"-e"},
		"bad binding":     {"-e", "Ax", "--", "cmd"},
		"empty entry":     {"-e", "A=", "--", "cmd"},
		"empty variable":  {"-e", "=x", "--", "cmd"},
		"duplicate":       {"-e", "A=x", "-e", "a=y", "--", "cmd"},
		"stray arg":       {"-e", "A=x", "cmd", "--", "cmd"},
		"unknown option":  {"--foo", "--", "cmd"},
		"no args at all":  nil,
		"separator first": {"--"},
	}
	for name, args := range cases {
		if _, _, err := parseRunArgs(args); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestMergeEnv(t *testing.T) {
	base := []string{"PATH=c:\\bin", "Token=old", "=C:=C:\\dir", "KEEP=1"}
	got := mergeEnv(base, map[string]string{"TOKEN": "new"})
	for _, kv := range []string{"PATH=c:\\bin", "=C:=C:\\dir", "KEEP=1", "TOKEN=new"} {
		if !slices.Contains(got, kv) {
			t.Errorf("missing %q in %v", kv, got)
		}
	}
	if slices.Contains(got, "Token=old") || len(got) != 4 {
		t.Errorf("old value not replaced: %v", got)
	}
}
