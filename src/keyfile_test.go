package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateKeyfile points the keyfile lookup at an empty directory so tests
// never depend on the real %LOCALAPPDATA% or WINPASS_KEYFILE.
func isolateKeyfile(t *testing.T) {
	t.Helper()
	t.Setenv(keyfileEnv, "")
	t.Setenv("LOCALAPPDATA", t.TempDir())

	// Point the TPM lookup at a key that cannot exist, so a real winpass TPM key does not leak in
	previous := tpmKeyName
	tpmKeyName = "winpass-test-missing"
	t.Cleanup(func() { tpmKeyName = previous })
}

func TestCreateKeyfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "k.kf")
	if err := createKeyfile(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != keyfileSize {
		t.Fatalf("len=%d err=%v", len(raw), err)
	}
	if bytes.Equal(raw, make([]byte, keyfileSize)) {
		t.Fatal("keyfile is all zeros")
	}
	if err := createKeyfile(path); err == nil {
		t.Fatal("existing keyfile was overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("existing keyfile content changed")
	}
}

func TestLoadKeyfile(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.kf"), filepath.Join(dir, "b.kf")
	if err := createKeyfile(a); err != nil {
		t.Fatal(err)
	}
	if err := createKeyfile(b); err != nil {
		t.Fatal(err)
	}

	keyA, idA, err := loadKeyfile(a)
	if err != nil || len(keyA) != blobKeySize {
		t.Fatalf("len=%d err=%v", len(keyA), err)
	}
	keyA2, idA2, _ := loadKeyfile(a)
	if !bytes.Equal(keyA, keyA2) || idA != idA2 {
		t.Fatal("same keyfile produced different key or ID")
	}
	keyB, idB, _ := loadKeyfile(b)
	if bytes.Equal(keyA, keyB) || idA == idB {
		t.Fatal("different keyfiles produced the same key or ID")
	}
	raw, _ := os.ReadFile(a)
	if bytes.Equal(keyA, raw) {
		t.Fatal("key equals the raw keyfile content")
	}
}

func TestLoadKeyfileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := loadKeyfile(filepath.Join(dir, "missing.kf")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing file: %v", err)
	}
	short := filepath.Join(dir, "short.kf")
	if err := os.WriteFile(short, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadKeyfile(short); err == nil || !strings.Contains(err.Error(), "exactly") {
		t.Fatalf("wrong size: %v", err)
	}
}

func TestKeyfilePath(t *testing.T) {
	t.Setenv(keyfileEnv, `C:\custom\my.kf`)
	if p, explicit := keyfilePath(); p != `C:\custom\my.kf` || !explicit {
		t.Fatalf("env override: %q %v", p, explicit)
	}

	t.Setenv(keyfileEnv, "")
	t.Setenv("LOCALAPPDATA", `C:\Users\x\AppData\Local`)
	p, explicit := keyfilePath()
	if explicit || !strings.HasSuffix(p, `winpass\winpass.kf`) || !strings.HasPrefix(p, `C:\Users\x\AppData\Local`) {
		t.Fatalf("default path: %q %v", p, explicit)
	}

	t.Setenv("LOCALAPPDATA", "")
	if p, _ := keyfilePath(); p != "" {
		t.Fatalf("expected no location, got %q", p)
	}
}

func TestChooseMode(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "k.kf")
	if err := createKeyfile(existing); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.kf")

	cases := []struct {
		name     string
		path     string
		explicit bool
		want     byte
		wantErr  bool
	}{
		{"no location", "", false, modeDefault, false},
		{"default present", existing, false, modeKeyfile, false},
		{"explicit present", existing, true, modeKeyfile, false},
		{"default missing falls back", missing, false, modeDefault, false},
		{"explicit missing is an error", missing, true, 0, true},
	}
	for _, c := range cases {
		got, err := chooseMode(c.path, c.explicit)
		if (err != nil) != c.wantErr || (!c.wantErr && got != c.want) {
			t.Fatalf("%s: got %d, %v", c.name, got, err)
		}
	}
}

func TestKeyfileModeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.kf"), filepath.Join(dir, "b.kf")
	if err := createKeyfile(a); err != nil {
		t.Fatal(err)
	}
	if err := createKeyfile(b); err != nil {
		t.Fatal(err)
	}

	t.Setenv(keyfileEnv, a)
	blob, err := encryptEntryWithMode(modeKeyfile, "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if mode, _, _ := parseBlobHeader(blob); mode != modeKeyfile {
		t.Fatalf("mode = %d", mode)
	}
	if got, err := decryptEntry("x", blob); err != nil || got != "pw" {
		t.Fatalf("got %q, %v", got, err)
	}

	// A different keyfile must be rejected by key ID, not by a GCM failure
	t.Setenv(keyfileEnv, b)
	if _, err := decryptEntry("x", blob); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("expected a different-key error, got %v", err)
	}

	// A missing keyfile is reported as such
	t.Setenv(keyfileEnv, filepath.Join(dir, "gone.kf"))
	if _, err := decryptEntry("x", blob); err == nil || !strings.Contains(err.Error(), "keyfile not found") {
		t.Fatalf("expected a keyfile-not-found error, got %v", err)
	}
}

func TestEntryUsesKey(t *testing.T) {
	id := keyID{1, 2, 3, 4}
	other := keyID{9, 9, 9, 9}
	blob, _ := sealBlob(modeKeyfile, id, testKey(1), "x", "pw")
	def, _ := sealBlob(modeDefault, keyID{}, testKey(1), "x", "pw")

	if !entryUsesKey(blob, modeKeyfile, nil) || !entryUsesKey(blob, modeKeyfile, &id) {
		t.Fatal("keyfile entry not matched")
	}
	if entryUsesKey(blob, modeKeyfile, &other) {
		t.Fatal("entry matched a different key ID")
	}
	if entryUsesKey(def, modeKeyfile, nil) || entryUsesKey([]byte("plain"), modeKeyfile, nil) {
		t.Fatal("non-keyfile entry matched")
	}
}

func TestSamePath(t *testing.T) {
	if !samePath(`C:\A\b.kf`, `c:\a\.\b.kf`) {
		t.Fatal("equivalent paths not matched")
	}
	if samePath(`C:\a\b.kf`, `C:\a\c.kf`) || samePath("", "x") {
		t.Fatal("different paths matched")
	}
}
