package main

import (
	"fmt"
	"os"
	"sort"
)

const verifyUsage = "usage: winpass verify <file> [<name> [--clip[=line], -c[line]]]"

// entryDiff is the comparison between a backup and the current store.
type entryDiff struct {
	matching       int
	differing      []string // present in both, values differ
	missingInStore []string // in the backup only
	notInBackup    []string // in the store only
}

// diffEntries compares a decrypted backup with the readable store entries.
func diffEntries(backup, store map[string]string) entryDiff {
	var d entryDiff
	for name, backupValue := range backup {
		storeValue, ok := store[name]
		switch {
		case !ok:
			d.missingInStore = append(d.missingInStore, name)
		case storeValue == backupValue:
			d.matching++
		default:
			d.differing = append(d.differing, name)
		}
	}
	for name := range store {
		if _, ok := backup[name]; !ok {
			d.notInBackup = append(d.notInBackup, name)
		}
	}
	sort.Strings(d.differing)
	sort.Strings(d.missingInStore)
	sort.Strings(d.notInBackup)
	return d
}

// cmdVerify checks an export file without importing it. With only a file it
// authenticates the backup and compares it with the store, never printing a
// value. With a name it prints or copies that single entry, which also works
// as a recovery path when the store itself is unreadable.
func cmdVerify(args []string) error {
	opts, err := parseOptions(args, []flagSpec{{short: 'c', long: "clip", optValue: true}})
	if err != nil {
		return err
	}
	if len(opts.positional) < 1 || len(opts.positional) > 2 {
		return fmt.Errorf(verifyUsage)
	}
	if opts.flags["clip"] && len(opts.positional) != 2 {
		return fmt.Errorf(verifyUsage)
	}

	data, err := os.ReadFile(opts.positional[0])
	if err != nil {
		return err
	}

	fmt.Print("Enter passphrase: ")
	passphrase, err := readPassword()
	fmt.Println()
	if err != nil {
		return err
	}

	// A successful GCM open proves the passphrase and the file integrity
	entries, err := decryptEntries(data, passphrase)
	if err != nil {
		return err
	}

	if len(opts.positional) == 2 {
		return showBackupEntry(entries, opts)
	}
	return reportBackup(entries)
}

func showBackupEntry(entries map[string]string, opts *parsedArgs) error {
	name := opts.positional[1]
	value, ok := entries[name]
	if !ok {
		return fmt.Errorf("entry not found in backup: %s", name)
	}

	if opts.flags["clip"] {
		line := opts.values["clip"]
		if line == 0 {
			line = 1
		}
		text, ok := nthLine(value, line)
		if !ok {
			return fmt.Errorf("there is no line %d in %s", line, name)
		}
		return copyToClipboard(text)
	}
	fmt.Println(value)
	return nil
}

func reportBackup(entries map[string]string) error {
	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	store := make(map[string]string, len(names))
	var unreadable []string
	for _, n := range names {
		value, err := credRead(n)
		if err != nil {
			unreadable = append(unreadable, n)
			continue
		}
		store[n] = value
	}
	sort.Strings(unreadable)

	d := diffEntries(entries, store)

	fmt.Printf("Backup OK: %d entries, decrypted and authenticated.\n", len(entries))
	fmt.Printf("Match the store:        %d\n", d.matching)
	fmt.Printf("Differ from the store:  %d\n", len(d.differing))
	fmt.Printf("Only in the backup:     %d\n", len(d.missingInStore))
	fmt.Printf("Only in the store:      %d\n", len(d.notInBackup))
	if len(unreadable) > 0 {
		fmt.Printf("Unreadable in store:    %d\n", len(unreadable))
	}
	printNames("differs", d.differing)
	printNames("only in backup", d.missingInStore)
	printNames("only in store", d.notInBackup)
	printNames("unreadable in store", unreadable)

	// Entries only in the backup are fine: the backup still covers the store
	if len(d.differing) > 0 || len(d.notInBackup) > 0 || len(unreadable) > 0 {
		return fmt.Errorf("the backup does not fully cover the current store")
	}
	return nil
}

func printNames(label string, names []string) {
	for _, n := range names {
		fmt.Printf("  %s: %s\n", label, n)
	}
}
