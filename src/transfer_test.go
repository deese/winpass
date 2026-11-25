package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckExportTarget(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "new.wpx")
	if err := checkExportTarget(missing); err != nil {
		t.Fatalf("missing file rejected: %v", err)
	}

	existing := filepath.Join(dir, "old.wpx")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkExportTarget(existing); err == nil {
		t.Fatal("existing file accepted")
	}
}
