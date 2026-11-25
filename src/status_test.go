package main

import "testing"

func TestCountEntryModes(t *testing.T) {
	def, _ := sealBlob(modeDefault, keyID{}, testKey(1), "a", "pw")
	kf, _ := sealBlob(modeKeyfile, keyID{1, 1, 1, 1}, testKey(1), "b", "pw")
	tpm1, _ := sealBlob(modeTPM, keyID{2, 2, 2, 2}, testKey(1), "c", "pw")
	tpm2, _ := sealBlob(modeTPM, keyID{2, 2, 2, 2}, testKey(1), "d", "pw")

	c := countEntryModes([][]byte{def, kf, tpm1, tpm2, []byte("legacy"), nil})
	if c.byMode[modeDefault] != 1 || c.byMode[modeKeyfile] != 1 || c.byMode[modeTPM] != 2 {
		t.Fatalf("byMode = %v", c.byMode)
	}
	if c.plaintext != 2 {
		t.Fatalf("plaintext = %d, want 2 (legacy and empty)", c.plaintext)
	}
}

func TestModeLabel(t *testing.T) {
	for mode, want := range map[byte]string{modeDefault: "default", modeKeyfile: "keyfile", modeTPM: "tpm"} {
		if got := modeLabel(mode); got != want {
			t.Fatalf("mode %d: got %q, want %q", mode, got, want)
		}
	}
	if got := modeLabel(99); got != "unknown(99)" {
		t.Fatalf("got %q", got)
	}
}
