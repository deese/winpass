package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// TPM mode derives the AES key from a deterministic signature: an RSA key
// that never leaves the TPM signs a fixed challenge with PKCS#1 v1.5, and the
// signature feeds HKDF. Nothing else is stored. RSA PKCS#1 v1.5 is
// deterministic, unlike ECDSA, which is why it is used here.
const (
	modeTPM byte = 2

	tpmProviderName = "Microsoft Platform Crypto Provider"
	tpmKeyBits      = 2048
	tpmChallenge    = "winpass tpm challenge v1"
	tpmKeyInfo      = "winpass tpm key v1"
	tpmIDInfo       = "winpass tpm id v1"

	bcryptPadPKCS1 = 0x2
	ntBadKeyset    = 0x80090016 // NTE_BAD_KEYSET: what NCryptOpenKey returns for a missing key
	ntNotFound     = 0x80090011 // NTE_NOT_FOUND
)

// tpmKeyName is a variable so tests can use a throwaway key name.
var tpmKeyName = "winpass"

var errTPMUnavailable = errors.New("no TPM available")

var (
	ncrypt                = syscall.NewLazyDLL("ncrypt.dll")
	procNCOpenProvider    = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCOpenKey         = ncrypt.NewProc("NCryptOpenKey")
	procNCCreatePersisted = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCSetProperty     = ncrypt.NewProc("NCryptSetProperty")
	procNCFinalizeKey     = ncrypt.NewProc("NCryptFinalizeKey")
	procNCSignHash        = ncrypt.NewProc("NCryptSignHash")
	procNCDeleteKey       = ncrypt.NewProc("NCryptDeleteKey")
	procNCFreeObject      = ncrypt.NewProc("NCryptFreeObject")
)

type pkcs1PaddingInfo struct {
	algID *uint16
}

// ncryptStatus is a SECURITY_STATUS / HRESULT returned by CNG.
type ncryptStatus uint32

func (s ncryptStatus) Error() string {
	return fmt.Sprintf("0x%08X", uint32(s))
}

func checkNCrypt(op string, r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", op, ncryptStatus(r))
}

func isKeyMissing(err error) bool {
	var s ncryptStatus
	return errors.As(err, &s) && (s == ntBadKeyset || s == ntNotFound)
}

func freeHandle(h uintptr) {
	procNCFreeObject.Call(h)
}

func openTPMProvider() (uintptr, error) {
	name, err := syscall.UTF16PtrFromString(tpmProviderName)
	if err != nil {
		return 0, err
	}
	var hProv uintptr
	r, _, _ := procNCOpenProvider.Call(uintptr(unsafe.Pointer(&hProv)), uintptr(unsafe.Pointer(name)), 0)
	if err := checkNCrypt("NCryptOpenStorageProvider", r); err != nil {
		return 0, fmt.Errorf("%w: %v", errTPMUnavailable, err)
	}
	return hProv, nil
}

// openTPMKey opens the winpass key. found is false when it does not exist.
func openTPMKey(hProv uintptr) (hKey uintptr, found bool, err error) {
	name, err := syscall.UTF16PtrFromString(tpmKeyName)
	if err != nil {
		return 0, false, err
	}
	r, _, _ := procNCOpenKey.Call(hProv, uintptr(unsafe.Pointer(&hKey)), uintptr(unsafe.Pointer(name)), 0, 0)
	if err := checkNCrypt("NCryptOpenKey", r); err != nil {
		if isKeyMissing(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return hKey, true, nil
}

// tpmKeyExists reports whether the winpass TPM key exists. A machine without
// a usable TPM reports false rather than an error.
func tpmKeyExists() (bool, error) {
	hProv, err := openTPMProvider()
	if errors.Is(err, errTPMUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer freeHandle(hProv)

	hKey, found, err := openTPMKey(hProv)
	if err != nil {
		return false, err
	}
	if found {
		freeHandle(hKey)
	}
	return found, nil
}

// signTPMChallenge signs SHA-256(challenge) with PKCS#1 v1.5.
func signTPMChallenge(hKey uintptr) ([]byte, error) {
	digest := sha256.Sum256([]byte(tpmChallenge))
	algID, err := syscall.UTF16PtrFromString("SHA256")
	if err != nil {
		return nil, err
	}
	pad := pkcs1PaddingInfo{algID: algID}

	var size uint32
	r, _, _ := procNCSignHash.Call(hKey, uintptr(unsafe.Pointer(&pad)),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&size)), bcryptPadPKCS1)
	if err := checkNCrypt("NCryptSignHash (size)", r); err != nil {
		return nil, err
	}

	sig := make([]byte, size)
	r, _, _ = procNCSignHash.Call(hKey, uintptr(unsafe.Pointer(&pad)),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), bcryptPadPKCS1)
	if err := checkNCrypt("NCryptSignHash", r); err != nil {
		return nil, err
	}
	return sig[:size], nil
}

// tpmCache avoids a TPM round trip per entry within one process.
var tpmCache struct {
	name string
	key  []byte
	id   keyID
}

// tpmKey returns the AES key and key ID derived from the TPM key.
func tpmKey() ([]byte, keyID, error) {
	if tpmCache.name == tpmKeyName && tpmCache.key != nil {
		return tpmCache.key, tpmCache.id, nil
	}

	hProv, err := openTPMProvider()
	if err != nil {
		return nil, keyID{}, err
	}
	defer freeHandle(hProv)

	hKey, found, err := openTPMKey(hProv)
	if err != nil {
		return nil, keyID{}, err
	}
	if !found {
		return nil, keyID{}, fmt.Errorf("TPM key %q not found: it was removed or the TPM was cleared", tpmKeyName)
	}
	defer freeHandle(hKey)

	sig, err := signTPMChallenge(hKey)
	if err != nil {
		return nil, keyID{}, err
	}
	key, id, err := deriveTPMKey(sig)
	if err != nil {
		return nil, keyID{}, err
	}
	tpmCache.name, tpmCache.key, tpmCache.id = tpmKeyName, key, id
	return key, id, nil
}

// deriveTPMKey turns the signature into the AES key and a key ID. The two use
// different labels, so the ID reveals nothing about the key.
func deriveTPMKey(sig []byte) ([]byte, keyID, error) {
	key, err := hkdf.Key(sha256.New, sig, nil, tpmKeyInfo, blobKeySize)
	if err != nil {
		return nil, keyID{}, err
	}
	idBytes, err := hkdf.Key(sha256.New, sig, nil, tpmIDInfo, keyIDSize)
	if err != nil {
		return nil, keyID{}, err
	}
	var id keyID
	copy(id[:], idBytes)
	return key, id, nil
}

// createTPMKey creates the persistent RSA key inside the TPM and proves the
// signature is reproducible, since the whole scheme depends on it.
func createTPMKey() error {
	hProv, err := openTPMProvider()
	if err != nil {
		return err
	}
	defer freeHandle(hProv)

	existing, found, err := openTPMKey(hProv)
	if err != nil {
		return err
	}
	if found {
		freeHandle(existing)
		return fmt.Errorf("TPM key %q already exists", tpmKeyName)
	}

	name, err := syscall.UTF16PtrFromString(tpmKeyName)
	if err != nil {
		return err
	}
	algRSA, err := syscall.UTF16PtrFromString("RSA")
	if err != nil {
		return err
	}
	lengthProp, err := syscall.UTF16PtrFromString("Length")
	if err != nil {
		return err
	}

	var hKey uintptr
	r, _, _ := procNCCreatePersisted.Call(hProv, uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(algRSA)), uintptr(unsafe.Pointer(name)), 0, 0)
	if err := checkNCrypt("NCryptCreatePersistedKey", r); err != nil {
		return err
	}

	bits := uint32(tpmKeyBits)
	r, _, _ = procNCSetProperty.Call(hKey, uintptr(unsafe.Pointer(lengthProp)), uintptr(unsafe.Pointer(&bits)), 4, 0)
	if err := checkNCrypt("NCryptSetProperty", r); err != nil {
		freeHandle(hKey) // not finalized, so nothing was persisted
		return err
	}
	r, _, _ = procNCFinalizeKey.Call(hKey, 0)
	if err := checkNCrypt("NCryptFinalizeKey", r); err != nil {
		freeHandle(hKey)
		return err
	}

	first, err := signTPMChallenge(hKey)
	if err == nil {
		var second []byte
		second, err = signTPMChallenge(hKey)
		if err == nil && !bytes.Equal(first, second) {
			err = errors.New("TPM signatures are not deterministic, TPM mode cannot be used on this machine")
		}
	}
	if err != nil {
		// NCryptDeleteKey also releases the handle
		procNCDeleteKey.Call(hKey, 0)
		return err
	}
	freeHandle(hKey)
	return nil
}

// deleteTPMKey removes the winpass key from the TPM. It reports whether the
// key existed.
func deleteTPMKey() (bool, error) {
	hProv, err := openTPMProvider()
	if err != nil {
		return false, err
	}
	defer freeHandle(hProv)

	hKey, found, err := openTPMKey(hProv)
	if err != nil || !found {
		return false, err
	}
	// NCryptDeleteKey also releases the handle
	r, _, _ := procNCDeleteKey.Call(hKey, 0)
	if err := checkNCrypt("NCryptDeleteKey", r); err != nil {
		return true, err
	}
	tpmCache.key = nil
	return true, nil
}
