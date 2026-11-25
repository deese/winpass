package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	setupUsage        = "usage: winpass setup keyfile [--remove [--force]] [path]\n       winpass setup tpm [--remove [--force]]"
	keyfileBackupNote = "Back this file up offline, apart from your exports. Without it, every entry encrypted with it is lost."
)

func cmdSetup(args []string) error {
	if len(args) == 0 {
		return errors.New(setupUsage)
	}
	switch args[0] {
	case "keyfile":
		return cmdSetupKeyfile(args[1:])
	case "tpm":
		return cmdSetupTPM(args[1:])
	default:
		return errors.New(setupUsage)
	}
}

// confirmRemoval guards the deletion of a key. It blocks while entries still
// use the key unless force is set, and always asks the user to confirm.
func confirmRemoval(label string, count int, force bool) error {
	if count > 0 && !force {
		return fmt.Errorf("%d entries are encrypted with %s: run 'winpass migrate --to default' first, or use --force if they are already lost", count, label)
	}
	prompt := fmt.Sprintf("Delete %s?", label)
	if count > 0 {
		prompt = fmt.Sprintf("%d entries will become permanently unreadable. Delete %s anyway?", count, label)
	}
	if !confirm(prompt) {
		return errors.New("aborted")
	}
	return nil
}

func cmdSetupTPM(args []string) error {
	opts, err := parseOptions(args, []flagSpec{
		{long: "remove"},
		{short: 'f', long: "force"},
	})
	if err != nil {
		return err
	}
	if len(opts.positional) != 0 || (opts.flags["force"] && !opts.flags["remove"]) {
		return errors.New(setupUsage)
	}
	if opts.flags["remove"] {
		return removeTPMKey(opts.flags["force"])
	}
	return createTPMKeyInteractive()
}

func createTPMKeyInteractive() error {
	hProv, err := openTPMProvider()
	if err != nil {
		return err
	}
	freeHandle(hProv)

	exists, err := tpmKeyExists()
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("TPM key %q already exists", tpmKeyName)
	}

	fmt.Println("The key is created inside this machine's TPM and cannot be exported.")
	fmt.Println("Entries encrypted with it are lost if the TPM is cleared or replaced, so keep an export.")
	fmt.Println("Each command that reads or writes a TPM-encrypted entry waits for the TPM, which can take around a second.")
	if !confirm("Create the TPM key?") {
		return errors.New("aborted")
	}

	if err := createTPMKey(); err != nil {
		return err
	}
	if err := setTPMMarker(); err != nil {
		// Without the marker the key would never be used, so do not leave it behind
		deleteTPMKey()
		return fmt.Errorf("record TPM mode: %w", err)
	}
	fmt.Println("TPM key created and its signature verified as reproducible.")

	active, err := activeMode()
	if err != nil {
		return err
	}
	fmt.Printf("Active mode for new entries: %s. Run 'winpass migrate' to convert existing ones.\n", modeLabel(active))
	if active != modeTPM {
		fmt.Println("A keyfile takes priority over the TPM; use 'winpass migrate --to tpm' to move entries to the TPM anyway.")
	}
	return nil
}

func removeTPMKey(force bool) error {
	exists, err := tpmKeyExists()
	if err != nil {
		return err
	}

	// Counts every TPM-mode entry: there is only one winpass TPM key
	count, err := countEntriesUsingKey(modeTPM, nil)
	if err != nil {
		return err
	}
	marked, err := hasTPMMarker()
	if err != nil {
		return err
	}
	if !exists {
		if !marked && count == 0 {
			return errors.New("no winpass TPM key found")
		}
		// The key is gone (TPM cleared or replaced). Clear the marker so
		// winpass stops selecting a mode that cannot work.
		if err := clearTPMMarker(); err != nil {
			return err
		}
		fmt.Println("No winpass TPM key found; TPM mode is now disabled.")
		if count > 0 {
			fmt.Printf("%d entries are encrypted with it and unreadable; delete them with 'winpass rm'.\n", count)
		}
		return nil
	}

	if err := confirmRemoval("the winpass TPM key", count, force); err != nil {
		return err
	}
	if _, err := deleteTPMKey(); err != nil {
		return err
	}
	if err := clearTPMMarker(); err != nil {
		return err
	}
	fmt.Println("TPM key removed.")
	if count > 0 {
		fmt.Printf("%d entries are now unreadable; delete them with 'winpass rm'.\n", count)
	}
	return nil
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

	if err := confirmRemoval("keyfile "+path, count, force); err != nil {
		return err
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
