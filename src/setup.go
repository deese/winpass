package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	setupUsage        = "usage: winpass setup keyfile [--remove [--force]] [path]"
	keyfileBackupNote = "Back this file up offline, apart from your exports. Without it, every entry encrypted with it is lost."
)

func cmdSetup(args []string) error {
	if len(args) == 0 || args[0] != "keyfile" {
		return errors.New(setupUsage)
	}
	return cmdSetupKeyfile(args[1:])
}

func cmdSetupKeyfile(args []string) error {
	opts, err := parseOptions(args, []flagSpec{
		{long: "remove"},
		{short: 'f', long: "force"},
	})
	if err != nil {
		return err
	}
	if len(opts.positional) > 1 || (opts.flags["force"] && !opts.flags["remove"]) {
		return errors.New(setupUsage)
	}

	path, err := setupKeyfileTarget(opts.positional)
	if err != nil {
		return err
	}

	if opts.flags["remove"] {
		return removeKeyfile(path, opts.flags["force"])
	}
	return createKeyfileAt(path)
}

// setupKeyfileTarget resolves the keyfile path from an explicit argument or
// from the configured location.
func setupKeyfileTarget(positional []string) (string, error) {
	if len(positional) == 1 {
		return filepath.Abs(positional[0])
	}
	path, _ := keyfilePath()
	if path == "" {
		return "", fmt.Errorf("cannot determine a default keyfile location: pass a path or set %s", keyfileEnv)
	}
	return path, nil
}

func createKeyfileAt(path string) error {
	if err := createKeyfile(path); err != nil {
		return err
	}
	fmt.Printf("Keyfile created: %s\n%s\n", path, keyfileBackupNote)

	active, _ := keyfilePath()
	if samePath(active, path) {
		fmt.Println("It is now the active key. New entries use it; run 'winpass migrate' to convert existing ones.")
		return nil
	}
	fmt.Printf("To use it, set the variable and then run 'winpass migrate':\n  setx %s \"%s\"\n", keyfileEnv, path)
	return nil
}

func removeKeyfile(path string, force bool) error {
	_, id, loadErr := loadKeyfile(path)
	if loadErr != nil {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("keyfile not found: %s", path)
		}
	}

	// An unreadable keyfile has no ID: count every keyfile-mode entry
	var idFilter *keyID
	if loadErr == nil {
		idFilter = &id
	}
	count, err := countEntriesUsingKey(modeKeyfile, idFilter)
	if err != nil {
		return err
	}

	if count > 0 && !force {
		return fmt.Errorf("%d entries are encrypted with this keyfile: run 'winpass migrate --to default' first, or use --force if they are already lost", count)
	}
	prompt := fmt.Sprintf("Delete keyfile %s?", path)
	if count > 0 {
		prompt = fmt.Sprintf("%d entries will become permanently unreadable. Delete %s anyway?", count, path)
	}
	if !confirm(prompt) {
		return errors.New("aborted")
	}

	if err := os.Remove(path); err != nil {
		return err
	}
	fmt.Printf("Keyfile removed: %s\n", path)
	if count > 0 {
		fmt.Printf("%d entries are now unreadable; delete them with 'winpass rm'.\n", count)
	}
	return nil
}

// countEntriesUsingKey counts stored entries encrypted with a mode and, when
// id is given, that exact key. It reads headers only and never decrypts.
func countEntriesUsingKey(mode byte, id *keyID) (int, error) {
	names, err := credEnumerate("")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, name := range names {
		blob, err := credReadRaw(name)
		if err != nil {
			// Cannot prove the entry is unrelated, so refuse to guess
			return 0, fmt.Errorf("read %s: %w", name, err)
		}
		if entryUsesKey(blob, mode, id) {
			count++
		}
	}
	return count, nil
}

func entryUsesKey(blob []byte, mode byte, id *keyID) bool {
	blobMode, blobID, encrypted := parseBlobHeader(blob)
	if !encrypted || blobMode != mode {
		return false
	}
	return id == nil || blobID == *id
}

// samePath compares Windows paths ignoring case and redundant separators.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
