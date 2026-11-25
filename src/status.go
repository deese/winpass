package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
)

// modeCounts tallies stored entries by the key mode named in their header.
type modeCounts struct {
	byMode    map[byte]int
	plaintext int // legacy entries without a winpass header
}

// countEntryModes reads headers only; nothing is decrypted.
func countEntryModes(blobs [][]byte) modeCounts {
	c := modeCounts{byMode: map[byte]int{}}
	for _, blob := range blobs {
		mode, _, encrypted := parseBlobHeader(blob)
		if !encrypted {
			c.plaintext++
			continue
		}
		c.byMode[mode]++
	}
	return c
}

// cmdStatus reports which key mode is active and how entries are stored. It
// never derives a key, so it does not wait for the TPM.
func cmdStatus(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: winpass status")
	}

	if mode, err := activeMode(); err != nil {
		fmt.Printf("Active mode (new entries): ERROR: %v\n", err)
	} else {
		fmt.Printf("Active mode (new entries): %s\n", modeLabel(mode))
	}
	fmt.Println("Priority: keyfile, then tpm, then default")
	fmt.Printf("Keyfile: %s\n", keyfileStatus())
	tpmText, tpmPresent := tpmStatus()
	fmt.Printf("TPM key: %s\n", tpmText)
	if marked, err := hasTPMMarker(); err == nil && marked && !tpmPresent {
		fmt.Println("WARNING: TPM mode is enabled but the key is missing: writes will fail. Run 'winpass setup tpm --remove' to disable it, or 'winpass setup tpm' to create a new key.")
	}

	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	blobs := make([][]byte, 0, len(names))
	unreadable := 0
	for _, name := range names {
		blob, err := credReadRaw(name)
		if err != nil {
			unreadable++
			continue
		}
		blobs = append(blobs, blob)
	}

	counts := countEntryModes(blobs)
	fmt.Printf("Entries: %d\n", len(names))
	modes := make([]int, 0, len(counts.byMode))
	for m := range counts.byMode {
		modes = append(modes, int(m))
	}
	sort.Ints(modes)
	for _, m := range modes {
		fmt.Printf("  %s: %d\n", modeLabel(byte(m)), counts.byMode[byte(m)])
	}
	if counts.plaintext > 0 {
		fmt.Printf("  unencrypted (legacy): %d, run 'winpass migrate'\n", counts.plaintext)
	}
	if unreadable > 0 {
		fmt.Printf("  could not be read: %d\n", unreadable)
	}
	return nil
}

func keyfileStatus() string {
	path, explicit := keyfilePath()
	if path == "" {
		return "no location configured"
	}
	source := "default location"
	if explicit {
		source = keyfileEnv
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Sprintf("not present (%s: %s)", source, path)
		}
		return fmt.Sprintf("cannot be checked (%s: %s): %v", source, path, err)
	}
	return fmt.Sprintf("present (%s: %s)", source, path)
}

// tpmStatus describes the TPM key and reports whether it exists.
func tpmStatus() (text string, present bool) {
	hProv, err := openTPMProvider()
	if err != nil {
		return "no TPM available", false
	}
	defer freeHandle(hProv)

	hKey, found, err := openTPMKey(hProv)
	if err != nil {
		return fmt.Sprintf("cannot be checked: %v", err), false
	}
	if !found {
		return fmt.Sprintf("not created (TPM available, key name %q)", tpmKeyName), false
	}
	freeHandle(hKey)
	return fmt.Sprintf("present (key name %q)", tpmKeyName), true
}
