package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

const (
	exportMagic      = "WPX1"
	exportSaltSize   = 16
	exportKeySize    = 32
	exportIterations = 600000
	// magic + salt + iterations (uint32) + GCM nonce (12 bytes)
	exportHeaderSize = len(exportMagic) + exportSaltSize + 4 + 12
)

func cmdExport(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: winpass export <file>")
	}
	path := args[0]

	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no passwords to export")
	}
	sort.Strings(names)

	entries := make(map[string]string, len(names))
	for _, n := range names {
		value, err := credRead(n)
		if err != nil {
			return err
		}
		entries[n] = value
	}

	passphrase, err := promptNewPassphrase()
	if err != nil {
		return err
	}

	data, err := encryptEntries(entries, passphrase)
	if err != nil {
		return err
	}

	// O_EXCL: never overwrite an existing export
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	fmt.Printf("Exported %d entries to %s.\n", len(entries), path)
	return nil
}

func cmdImport(args []string) error {
	force := false
	path := ""
	for _, a := range args {
		if a == "-f" || a == "--force" {
			force = true
		} else {
			path = a
		}
	}
	if path == "" {
		return fmt.Errorf("usage: winpass import [-f] <file>")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fmt.Print("Enter passphrase: ")
	passphrase, err := readPassword()
	fmt.Println()
	if err != nil {
		return err
	}

	entries, err := decryptEntries(data, passphrase)
	if err != nil {
		return err
	}

	existing, err := credEnumerate("")
	if err != nil {
		return err
	}
	exists := make(map[string]bool, len(existing))
	for _, n := range existing {
		exists[n] = true
	}

	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)

	imported, skipped, failed := 0, 0, 0
	for _, n := range names {
		if exists[n] && !force {
			skipped++
			continue
		}
		if err := credWrite(n, entries[n]); err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s: %v\n", n, err)
			failed++
			continue
		}
		imported++
	}
	fmt.Printf("Imported %d, skipped %d (already exist, use -f to overwrite), failed %d.\n", imported, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d entries failed to import", failed)
	}
	return nil
}

func promptNewPassphrase() (string, error) {
	fmt.Print("Enter passphrase for the export: ")
	p1, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Print("\nRetype passphrase: ")
	p2, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Println()
	if p1 == "" {
		return "", fmt.Errorf("passphrase must not be empty")
	}
	if p1 != p2 {
		return "", fmt.Errorf("passphrases do not match")
	}
	return p1, nil
}

func deriveKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, iterations, exportKeySize)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encryptEntries layout: magic | salt | iterations | nonce | ciphertext.
// The header is authenticated as GCM additional data.
func encryptEntries(entries map[string]string, passphrase string) ([]byte, error) {
	plaintext, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}

	header := make([]byte, exportHeaderSize)
	copy(header, exportMagic)
	salt := header[len(exportMagic) : len(exportMagic)+exportSaltSize]
	iterOffset := len(exportMagic) + exportSaltSize
	binary.BigEndian.PutUint32(header[iterOffset:], exportIterations)
	nonce := header[iterOffset+4:]
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	key, err := deriveKey(passphrase, salt, exportIterations)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(header, nonce, plaintext, header), nil
}

func decryptEntries(data []byte, passphrase string) (map[string]string, error) {
	if len(data) < exportHeaderSize || !bytes.HasPrefix(data, []byte(exportMagic)) {
		return nil, errors.New("not a winpass export file")
	}
	header := data[:exportHeaderSize]
	salt := header[len(exportMagic) : len(exportMagic)+exportSaltSize]
	iterOffset := len(exportMagic) + exportSaltSize
	iterations := binary.BigEndian.Uint32(header[iterOffset:])
	nonce := header[iterOffset+4:]

	// Guard against a crafted header forcing an unbounded KDF run
	if iterations == 0 || iterations > 10*exportIterations {
		return nil, errors.New("invalid export header")
	}

	key, err := deriveKey(passphrase, salt, int(iterations))
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, data[exportHeaderSize:], header)
	if err != nil {
		return nil, errors.New("wrong passphrase or corrupted file")
	}

	var entries map[string]string
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}
