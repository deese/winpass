package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// modeNames maps the --to values to key modes. Modes are added here as they
// are implemented.
var modeNames = map[string]byte{
	"default": modeDefault,
	"keyfile": modeKeyfile,
	"tpm":     modeTPM,
}

const migrateUsage = "usage: winpass migrate [--to default|keyfile|tpm] [--skip-backup]"

type migrateOptions struct {
	target     byte
	skipBackup bool
}

func parseMigrateArgs(args []string) (*migrateOptions, error) {
	opts := &migrateOptions{}
	targetName := ""

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--skip-backup":
			opts.skipBackup = true
		case a == "--to":
			if i+1 >= len(args) {
				return nil, errors.New(migrateUsage)
			}
			i++
			targetName = args[i]
		case strings.HasPrefix(a, "--to="):
			targetName = strings.TrimPrefix(a, "--to=")
		default:
			return nil, errors.New(migrateUsage)
		}
	}

	if targetName == "" {
		mode, err := activeMode()
		if err != nil {
			return nil, err
		}
		opts.target = mode
		return opts, nil
	}
	mode, ok := modeNames[targetName]
	if !ok {
		return nil, fmt.Errorf("unknown or unavailable mode %q", targetName)
	}
	opts.target = mode
	return opts, nil
}

// migrateBlob re-encrypts one stored blob with the target mode. It returns
// changed=false when the blob already uses the target mode and key.
func migrateBlob(name string, blob []byte, target byte) (newBlob []byte, changed bool, err error) {
	_, targetID, err := keyForMode(target)
	if err != nil {
		return nil, false, err
	}
	if mode, id, encrypted := parseBlobHeader(blob); encrypted && mode == target && id == targetID {
		return blob, false, nil
	}

	plaintext, err := decryptEntry(name, blob)
	if err != nil {
		return nil, false, err
	}
	newBlob, err = encryptEntryWithMode(target, name, plaintext)
	if err != nil {
		return nil, false, err
	}

	// Prove the new blob is readable before it replaces the old one
	check, err := decryptEntry(name, newBlob)
	if err != nil || check != plaintext {
		return nil, false, errors.New("re-encrypted entry failed verification")
	}
	return newBlob, !bytes.Equal(blob, newBlob), nil
}

// cmdMigrate re-encrypts every entry with the target mode. Each CredWriteW
// replaces one entry atomically, so an interrupted run can simply be repeated.
func cmdMigrate(args []string) error {
	opts, err := parseMigrateArgs(args)
	if err != nil {
		return err
	}
	if _, _, err := keyForMode(opts.target); err != nil {
		return err
	}

	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Println("No passwords stored.")
		return nil
	}
	sort.Strings(names)

	if !opts.skipBackup && !confirm("Migration rewrites every entry. Did you make a recent backup with 'winpass export'?") {
		return errors.New("aborted: make a backup first, or pass --skip-backup")
	}

	// The legacy warning points at this command, so it is noise here
	legacyWarned = true

	migrated, skipped, failed := 0, 0, 0
	for _, name := range names {
		blob, err := credReadRaw(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s: %v\n", name, err)
			failed++
			continue
		}
		newBlob, changed, err := migrateBlob(name, blob, opts.target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s: %v\n", name, err)
			failed++
			continue
		}
		if !changed {
			skipped++
			continue
		}
		if err := credWriteRaw(name, newBlob); err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s: %v\n", name, err)
			failed++
			continue
		}
		migrated++
	}

	fmt.Printf("Migrated %d, already up to date %d, failed %d.\n", migrated, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d entries failed to migrate", failed)
	}
	return nil
}
