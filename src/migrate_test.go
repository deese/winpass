package main

import (
	"bytes"
	"testing"
)

func TestMigrateBlobLegacyToDefault(t *testing.T) {
	legacy := []byte("plain password")
	newBlob, changed, err := migrateBlob("old", legacy, modeDefault)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	got, err := decryptEntry("old", newBlob)
	if err != nil || got != "plain password" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestMigrateBlobSkipsUpToDate(t *testing.T) {
	blob, err := encryptEntryWithMode(modeDefault, "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	newBlob, changed, err := migrateBlob("x", blob, modeDefault)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !bytes.Equal(newBlob, blob) {
		t.Fatal("up-to-date blob was modified")
	}
}

func TestMigrateBlobEmptyLegacy(t *testing.T) {
	newBlob, changed, err := migrateBlob("empty", nil, modeDefault)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got, err := decryptEntry("empty", newBlob); err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestMigrateBlobFailsOnUnreadableSource(t *testing.T) {
	blob, _ := sealBlob(200, keyID{}, testKey(9), "x", "pw") // mode with no resolvable key
	if _, _, err := migrateBlob("x", blob, modeDefault); err == nil {
		t.Fatal("entry that cannot be decrypted was migrated")
	}
}

func TestMigrateBlobRejectsUnsupportedTarget(t *testing.T) {
	if _, _, err := migrateBlob("x", []byte("pw"), 200); err == nil {
		t.Fatal("unsupported target mode was accepted")
	}
}

func TestParseMigrateArgs(t *testing.T) {
	cases := []struct {
		args    []string
		wantErr bool
		skip    bool
	}{
		{nil, false, false},
		{[]string{"--to", "default"}, false, false},
		{[]string{"--to=default", "--skip-backup"}, false, true},
		{[]string{"--to"}, true, false},
		{[]string{"--to", "nope"}, true, false},
		{[]string{"extra"}, true, false},
	}
	for _, c := range cases {
		opts, err := parseMigrateArgs(c.args)
		if (err != nil) != c.wantErr {
			t.Fatalf("%v: err=%v, wantErr=%v", c.args, err, c.wantErr)
		}
		if err == nil && opts.skipBackup != c.skip {
			t.Fatalf("%v: skipBackup=%v, want %v", c.args, opts.skipBackup, c.skip)
		}
	}
}
