package main

import (
	"bytes"
	"strings"
	"testing"
)

func testKey(b byte) []byte {
	return bytes.Repeat([]byte{b}, blobKeySize)
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(1)
	blob, err := sealBlob(modeDefault, keyID{}, key, "web/site", "s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte(blobMagic)) {
		t.Fatal("blob is missing the magic prefix")
	}
	if bytes.Contains(blob, []byte("s3cr3t")) {
		t.Fatal("plaintext leaked into the blob")
	}
	got, err := openBlob(key, "web/site", blob)
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cr3t" {
		t.Fatalf("got %q, want %q", got, "s3cr3t")
	}
}

func TestSealEmptyPlaintext(t *testing.T) {
	key := testKey(1)
	blob, err := sealBlob(modeDefault, keyID{}, key, "empty", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := openBlob(key, "empty", blob)
	if err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	key := testKey(1)
	a, _ := sealBlob(modeDefault, keyID{}, key, "x", "same")
	b, _ := sealBlob(modeDefault, keyID{}, key, "x", "same")
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same value produced identical blobs")
	}
}

func TestOpenRejectsOtherEntryName(t *testing.T) {
	key := testKey(1)
	blob, _ := sealBlob(modeDefault, keyID{}, key, "bank", "pw")
	if _, err := openBlob(key, "test", blob); err == nil {
		t.Fatal("ciphertext moved to another entry name was accepted")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	blob, _ := sealBlob(modeDefault, keyID{}, testKey(1), "x", "pw")
	if _, err := openBlob(testKey(2), "x", blob); err == nil {
		t.Fatal("wrong key was accepted")
	}
}

func TestOpenRejectsTamperedHeader(t *testing.T) {
	key := testKey(1)
	blob, _ := sealBlob(modeDefault, keyID{}, key, "x", "pw")
	blob[len(blobMagic)] ^= 0xff // rewrite the mode byte
	if _, err := openBlob(key, "x", blob); err == nil {
		t.Fatal("tampered header was accepted")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key := testKey(1)
	blob, _ := sealBlob(modeDefault, keyID{}, key, "x", "pw")
	blob[len(blob)-1] ^= 0x01
	if _, err := openBlob(key, "x", blob); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestParseBlobHeader(t *testing.T) {
	id := keyID{1, 2, 3, 4}
	blob, _ := sealBlob(7, id, testKey(1), "x", "pw")
	mode, gotID, encrypted := parseBlobHeader(blob)
	if !encrypted || mode != 7 || gotID != id {
		t.Fatalf("got mode=%d id=%v encrypted=%v", mode, gotID, encrypted)
	}
	if _, _, encrypted := parseBlobHeader([]byte("plain password")); encrypted {
		t.Fatal("legacy plaintext detected as encrypted")
	}
	if _, _, encrypted := parseBlobHeader(nil); encrypted {
		t.Fatal("empty blob detected as encrypted")
	}
}

func TestDecryptEntryLegacyPassthrough(t *testing.T) {
	got, err := decryptEntry("old", []byte("plain password"))
	if err != nil || got != "plain password" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = decryptEntry("old-empty", nil)
	if err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDecryptEntryTruncatedHeader(t *testing.T) {
	if _, err := decryptEntry("x", []byte(blobMagic)); err == nil {
		t.Fatal("truncated header was accepted")
	}
}

func TestDecryptEntryUnsupportedMode(t *testing.T) {
	blob, _ := sealBlob(200, keyID{}, testKey(1), "x", "pw")
	_, err := decryptEntry("x", blob)
	if err == nil || !strings.Contains(err.Error(), "unsupported key mode") {
		t.Fatalf("expected unsupported key mode error, got %v", err)
	}
}

func TestDefaultModeRoundTrip(t *testing.T) {
	isolateKeyfile(t)
	blob, err := encryptEntry("web/site", "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptEntry("web/site", blob)
	if err != nil || got != "pw" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDefaultKeyIsStable(t *testing.T) {
	a, err := deriveDefaultKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deriveDefaultKey()
	if !bytes.Equal(a, b) || len(a) != blobKeySize {
		t.Fatal("default key is not deterministic or has the wrong length")
	}
}

func TestBlobFitsLimitForTypicalPassword(t *testing.T) {
	blob, _ := sealBlob(modeDefault, keyID{}, testKey(1), "x", strings.Repeat("a", maxPlaintextSize))
	if len(blob) != maxBlobSize {
		t.Fatalf("blob is %d bytes, want exactly %d", len(blob), maxBlobSize)
	}
}
