package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Stored blob layout: magic | mode | key ID | nonce | ciphertext+tag.
// magic, mode and key ID form the header; the header and the entry name are
// authenticated as GCM additional data, so a ciphertext cannot be moved to
// another entry or have its mode rewritten without detection.
const (
	blobMagic     = "\x00WP2"
	keyIDSize     = 4
	blobNonceSize = 12
	blobKeySize   = 32
	blobHeaderLen = len(blobMagic) + 1 + keyIDSize
	// header + nonce + GCM tag
	blobOverhead = blobHeaderLen + blobNonceSize + 16
	// largest plaintext that still fits in a Windows credential blob
	maxPlaintextSize = maxBlobSize - blobOverhead

	modeDefault byte = 0
)

type keyID [keyIDSize]byte

var errUnsupportedMode = errors.New("unsupported key mode")

// The default key is machine-bound: HKDF(MachineGuid, salt=pepper). The pepper
// lives in a public repository, so it is not a secret. It is split in two
// masked halves only to keep it out of a plain `strings` dump of the binary.
// The protection comes from the MachineGuid not being part of the blob.
var (
	pepperA = [blobKeySize]byte{
		0x6c, 0xb8, 0xa8, 0x53, 0xa3, 0x86, 0x68, 0x13, 0xce, 0x35, 0x3c, 0x5d, 0xc6, 0x54, 0x75, 0xe2,
		0xc2, 0x38, 0x43, 0x46, 0xe1, 0x69, 0x28, 0x30, 0x82, 0x4b, 0x57, 0x00, 0xf7, 0xb6, 0x46, 0xcf,
	}
	pepperB = [blobKeySize]byte{
		0x28, 0x0b, 0x5b, 0xc7, 0x5c, 0x1a, 0x09, 0x6e, 0xe3, 0xf2, 0x93, 0x60, 0xea, 0xbd, 0xc2, 0xad,
		0x9d, 0xc9, 0xcc, 0x7e, 0x02, 0x7b, 0x06, 0x2c, 0x42, 0x6a, 0xee, 0x2f, 0x6d, 0x97, 0xdd, 0x20,
	}
)

const (
	machineGuidKey  = `SOFTWARE\Microsoft\Cryptography`
	machineGuidName = "MachineGuid"
	defaultKeyInfo  = "winpass default key v1"
)

// defaultKey is derived once per process.
var defaultKey = sync.OnceValues(deriveDefaultKey)

func deriveDefaultKey() ([]byte, error) {
	guid, err := readMachineGUID()
	if err != nil {
		return nil, err
	}
	pepper := make([]byte, blobKeySize)
	for i := range pepper {
		pepper[i] = pepperA[i] ^ pepperB[i]
	}
	return hkdf.Key(sha256.New, []byte(guid), pepper, defaultKeyInfo, blobKeySize)
}

func readMachineGUID() (string, error) {
	subkey, err := syscall.UTF16PtrFromString(machineGuidKey)
	if err != nil {
		return "", err
	}
	name, err := syscall.UTF16PtrFromString(machineGuidName)
	if err != nil {
		return "", err
	}

	// Explicit 64-bit view so a 32-bit build reads the same value
	var hKey syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_QUERY_VALUE|syscall.KEY_WOW64_64KEY, &hKey)
	if err != nil {
		return "", fmt.Errorf("open MachineGuid key: %w", err)
	}
	defer syscall.RegCloseKey(hKey)

	buf := make([]byte, 256)
	size := uint32(len(buf))
	var valueType uint32
	err = syscall.RegQueryValueEx(hKey, name, nil, &valueType, &buf[0], &size)
	if err != nil {
		return "", fmt.Errorf("read MachineGuid: %w", err)
	}
	if valueType != syscall.REG_SZ || size < 2 {
		return "", errors.New("unexpected MachineGuid value type")
	}

	units := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), size/2)
	guid := strings.ToLower(strings.TrimSpace(syscall.UTF16ToString(units)))
	if guid == "" {
		return "", errors.New("empty MachineGuid")
	}
	return guid, nil
}

// activeMode is the mode used for new writes.
func activeMode() (byte, error) {
	return modeDefault, nil
}

// keyForMode returns the key and key ID of a mode.
func keyForMode(mode byte) ([]byte, keyID, error) {
	switch mode {
	case modeDefault:
		key, err := defaultKey()
		return key, keyID{}, err
	default:
		return nil, keyID{}, fmt.Errorf("%w: %d", errUnsupportedMode, mode)
	}
}

// parseBlobHeader reports whether blob is a winpass encrypted blob. A blob
// without the magic prefix is a legacy plaintext entry.
func parseBlobHeader(blob []byte) (mode byte, id keyID, encrypted bool) {
	if !bytes.HasPrefix(blob, []byte(blobMagic)) {
		return 0, keyID{}, false
	}
	if len(blob) < blobHeaderLen {
		// Magic present but truncated: treated as encrypted so decoding fails loudly
		return 0, keyID{}, true
	}
	mode = blob[len(blobMagic)]
	copy(id[:], blob[len(blobMagic)+1:blobHeaderLen])
	return mode, id, true
}

func blobAAD(header []byte, name string) []byte {
	aad := make([]byte, 0, len(header)+len(name))
	aad = append(aad, header...)
	return append(aad, name...)
}

func sealBlob(mode byte, id keyID, key []byte, name, plaintext string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	blob := make([]byte, blobHeaderLen+blobNonceSize, blobHeaderLen+blobNonceSize+len(plaintext)+gcm.Overhead())
	copy(blob, blobMagic)
	blob[len(blobMagic)] = mode
	copy(blob[len(blobMagic)+1:], id[:])
	nonce := blob[blobHeaderLen:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	header := blob[:blobHeaderLen]
	return gcm.Seal(blob, nonce, []byte(plaintext), blobAAD(header, name)), nil
}

func openBlob(key []byte, name string, blob []byte) (string, error) {
	if len(blob) < blobOverhead {
		return "", errors.New("corrupted entry: blob too short")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	header := blob[:blobHeaderLen]
	nonce := blob[blobHeaderLen : blobHeaderLen+blobNonceSize]
	plaintext, err := gcm.Open(nil, nonce, blob[blobHeaderLen+blobNonceSize:], blobAAD(header, name))
	if err != nil {
		return "", errors.New("cannot decrypt entry: wrong key or corrupted data")
	}
	return string(plaintext), nil
}

// encryptEntry seals plaintext with the active mode.
func encryptEntry(name, plaintext string) ([]byte, error) {
	mode, err := activeMode()
	if err != nil {
		return nil, err
	}
	return encryptEntryWithMode(mode, name, plaintext)
}

// encryptEntryWithMode seals plaintext with an explicit mode.
func encryptEntryWithMode(mode byte, name, plaintext string) ([]byte, error) {
	key, id, err := keyForMode(mode)
	if err != nil {
		return nil, err
	}
	return sealBlob(mode, id, key, name, plaintext)
}

var legacyWarned bool

// decryptEntry opens a stored blob using the mode named in its header.
// Blobs without a header are legacy plaintext entries and are returned as-is
// with a one-time warning.
func decryptEntry(name string, blob []byte) (string, error) {
	mode, id, encrypted := parseBlobHeader(blob)
	if !encrypted {
		if len(blob) > 0 && !legacyWarned {
			legacyWarned = true
			fmt.Fprintf(os.Stderr, "winpass: warning: entry %q is stored without winpass encryption, run 'winpass migrate'\n", name)
		}
		return string(blob), nil
	}
	if len(blob) < blobHeaderLen {
		return "", errors.New("corrupted entry: truncated header")
	}

	key, wantID, err := keyForMode(mode)
	if err != nil {
		return "", fmt.Errorf("entry %q: %w", name, err)
	}
	if id != wantID {
		return "", fmt.Errorf("entry %q was encrypted with a different key", name)
	}
	plaintext, err := openBlob(key, name, blob)
	if err != nil {
		return "", fmt.Errorf("entry %q: %w", name, err)
	}
	return plaintext, nil
}
