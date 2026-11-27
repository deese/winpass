package main

import (
	"strings"
	"testing"
)

func TestMergePath(t *testing.T) {
	got := mergePath(`C:\a;C:\b\`, `c:\A;C:\c;;`, ``)
	want := `C:\a;C:\b\;C:\c`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := mergePath(`C:\a\PuTTY"`, `"C:\b"`); got != `C:\a\PuTTY;C:\b` {
		t.Fatalf("quotes not removed: %q", got)
	}
	if mergePath("", "") != "" {
		t.Fatal("empty lists should merge to empty")
	}
}

func TestPersistentPath(t *testing.T) {
	path := persistentPath()
	if !strings.Contains(strings.ToLower(path), `\windows\system32`) {
		t.Fatalf("persistent PATH should include System32, got %q", path)
	}
	if strings.Contains(path, "%") {
		t.Fatalf("persistent PATH has unexpanded variables: %q", path)
	}
}
