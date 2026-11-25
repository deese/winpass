package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// useThrowawayTPMKey points the package at a unique key name and deletes it
// afterwards, so tests never touch a real winpass TPM key.
func useThrowawayTPMKey(t *testing.T) {
	t.Helper()
	hProv, err := openTPMProvider()
	if errors.Is(err, errTPMUnavailable) {
		t.Skip("no TPM available")
	}
	if err != nil {
		t.Fatal(err)
	}
	freeHandle(hProv)

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	previous := tpmKeyName
	tpmKeyName = "winpass-test-" + hex.EncodeToString(suffix)
	t.Cleanup(func() {
		deleteTPMKey()
		clearTPMMarker()
		tpmKeyName = previous
		tpmCache.key = nil
	})
}

func TestDeriveTPMKey(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, 256)
	key, id, err := deriveTPMKey(sig)
	if err != nil || len(key) != blobKeySize {
		t.Fatalf("len=%d err=%v", len(key), err)
	}
	key2, id2, _ := deriveTPMKey(sig)
	if !bytes.Equal(key, key2) || id != id2 {
		t.Fatal("derivation is not deterministic")
	}
	other, otherID, _ := deriveTPMKey(bytes.Repeat([]byte{8}, 256))
	if bytes.Equal(key, other) || id == otherID {
		t.Fatal("different signatures produced the same key or ID")
	}
}

func TestTPMKeyLifecycle(t *testing.T) {
	useThrowawayTPMKey(t)

	if exists, err := tpmKeyExists(); err != nil || exists {
		t.Fatalf("fresh name: exists=%v err=%v", exists, err)
	}
	if _, _, err := tpmKey(); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected a not-found error, got %v", err)
	}

	if err := createTPMKey(); err != nil {
		t.Fatal(err)
	}
	if err := createTPMKey(); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second create: %v", err)
	}
	if exists, err := tpmKeyExists(); err != nil || !exists {
		t.Fatalf("after create: exists=%v err=%v", exists, err)
	}

	// Same key across independent derivations (the cache is bypassed)
	first, firstID, err := tpmKey()
	if err != nil {
		t.Fatal(err)
	}
	tpmCache.key = nil
	second, secondID, err := tpmKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || firstID != secondID {
		t.Fatal("TPM key is not reproducible")
	}

	// Full round trip through the mode dispatch
	blob, err := encryptEntryWithMode(modeTPM, "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if mode, _, _ := parseBlobHeader(blob); mode != modeTPM {
		t.Fatalf("mode = %d", mode)
	}
	if got, err := decryptEntry("x", blob); err != nil || got != "pw" {
		t.Fatalf("got %q, %v", got, err)
	}

	existed, err := deleteTPMKey()
	if err != nil || !existed {
		t.Fatalf("delete: existed=%v err=%v", existed, err)
	}
	if exists, _ := tpmKeyExists(); exists {
		t.Fatal("key still exists after delete")
	}
	if _, err := decryptEntry("x", blob); err == nil {
		t.Fatal("entry decrypted after the TPM key was deleted")
	}
}

func TestActiveModeUsesTPMWhenKeyExists(t *testing.T) {
	isolateKeyfile(t)
	useThrowawayTPMKey(t)

	if mode, err := activeMode(); err != nil || mode != modeDefault {
		t.Fatalf("before create: %d, %v", mode, err)
	}
	// The key alone does not change the mode: the setup marker does
	if err := createTPMKey(); err != nil {
		t.Fatal(err)
	}
	if mode, err := activeMode(); err != nil || mode != modeDefault {
		t.Fatalf("key without marker: %d, %v", mode, err)
	}
	if err := setTPMMarker(); err != nil {
		t.Fatal(err)
	}
	if mode, err := activeMode(); err != nil || mode != modeTPM {
		t.Fatalf("with marker: %d, %v", mode, err)
	}

	// A marker without a key must fail loudly on write, never downgrade
	if _, err := deleteTPMKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := encryptEntry("x", "pw"); err == nil {
		t.Fatal("write succeeded although the TPM key is gone")
	}
}

// A cleared TPM leaves the marker behind. --remove must be the way out.
func TestRemoveTPMKeyClearsStaleMarker(t *testing.T) {
	useThrowawayTPMKey(t)
	if err := setTPMMarker(); err != nil {
		t.Fatal(err)
	}
	if err := removeTPMKey(false); err != nil {
		t.Fatal(err)
	}
	if marked, _ := hasTPMMarker(); marked {
		t.Fatal("stale marker was not cleared")
	}
	if err := removeTPMKey(false); err == nil {
		t.Fatal("removing with nothing configured should report an error")
	}
}

func TestTPMMarker(t *testing.T) {
	previous := tpmKeyName
	tpmKeyName = "winpass-test-marker"
	t.Cleanup(func() {
		clearTPMMarker()
		tpmKeyName = previous
	})

	if marked, err := hasTPMMarker(); err != nil || marked {
		t.Fatalf("fresh: %v %v", marked, err)
	}
	if err := setTPMMarker(); err != nil {
		t.Fatal(err)
	}
	if marked, err := hasTPMMarker(); err != nil || !marked {
		t.Fatalf("after set: %v %v", marked, err)
	}
	names, err := credEnumerate("")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if strings.Contains(n, "winpass-config") {
			t.Fatalf("marker leaked into the entry listing: %s", n)
		}
	}
	if err := clearTPMMarker(); err != nil {
		t.Fatal(err)
	}
	if err := clearTPMMarker(); err != nil {
		t.Fatalf("clearing twice must be a no-op: %v", err)
	}
	if marked, _ := hasTPMMarker(); marked {
		t.Fatal("marker still set after clear")
	}
}
