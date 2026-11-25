package main

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	modeKeyfile byte = 1

	keyfileEnv         = "WINPASS_KEYFILE"
	keyfileDefaultPath = `winpass\winpass.kf` // relative to %LOCALAPPDATA%, which does not roam
	keyfileSize        = 32
	keyfileKeyInfo     = "winpass keyfile key v1"
	keyfileIDInfo      = "winpass keyfile id v1"
)

// keyfilePath returns the keyfile location. An empty path means there is no
// default location (no %LOCALAPPDATA%) and WINPASS_KEYFILE is unset.
func keyfilePath() (path string, explicit bool) {
	if p := os.Getenv(keyfileEnv); p != "" {
		return p, true
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return filepath.Join(base, keyfileDefaultPath), false
	}
	return "", false
}

// chooseMode picks the write mode from the keyfile state. A missing default
// keyfile means the default mode; a missing explicit one is an error, so a
// typo in WINPASS_KEYFILE cannot silently downgrade new writes.
func chooseMode(keyfile string, explicit bool) (byte, error) {
	if keyfile == "" {
		return modeDefault, nil
	}
	_, err := os.Stat(keyfile)
	switch {
	case err == nil:
		return modeKeyfile, nil
	case !errors.Is(err, os.ErrNotExist):
		return 0, err
	case explicit:
		return 0, fmt.Errorf("keyfile not found: %s (set by %s)", keyfile, keyfileEnv)
	}
	return modeDefault, nil
}

// loadKeyfile derives the encryption key and its ID from a keyfile. Both are
// derived with different labels, so the ID reveals nothing about the key.
func loadKeyfile(path string) ([]byte, keyID, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, keyID{}, fmt.Errorf("keyfile not found: %s", path)
		}
		return nil, keyID{}, fmt.Errorf("read keyfile: %w", err)
	}
	if len(raw) != keyfileSize {
		return nil, keyID{}, fmt.Errorf("keyfile %s must be exactly %d bytes, found %d", path, keyfileSize, len(raw))
	}

	key, err := hkdf.Key(sha256.New, raw, nil, keyfileKeyInfo, blobKeySize)
	if err != nil {
		return nil, keyID{}, err
	}
	idBytes, err := hkdf.Key(sha256.New, raw, nil, keyfileIDInfo, keyIDSize)
	if err != nil {
		return nil, keyID{}, err
	}
	var id keyID
	copy(id[:], idBytes)
	return key, id, nil
}

// keyfileCache avoids re-reading the file for every entry in one process.
var keyfileCache struct {
	path string
	key  []byte
	id   keyID
}

// keyfileKey returns the key for the configured keyfile.
func keyfileKey() ([]byte, keyID, error) {
	path, _ := keyfilePath()
	if path == "" {
		return nil, keyID{}, fmt.Errorf("no keyfile location: set %s", keyfileEnv)
	}
	if keyfileCache.path == path && keyfileCache.key != nil {
		return keyfileCache.key, keyfileCache.id, nil
	}
	key, id, err := loadKeyfile(path)
	if err != nil {
		return nil, keyID{}, err
	}
	keyfileCache.path, keyfileCache.key, keyfileCache.id = path, key, id
	return key, id, nil
}

// createKeyfile writes 32 random bytes. It never overwrites: a new keyfile
// over an existing one would orphan every entry encrypted with the old one.
func createKeyfile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists, refusing to overwrite", path)
		}
		return err
	}

	key := make([]byte, keyfileSize)
	if _, err := rand.Read(key); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
