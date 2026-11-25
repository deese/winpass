package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	maxBlobSize             = 2560
	storePrefix             = "winpass/"
)

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procCredReadW      = advapi32.NewProc("CredReadW")
	procCredWriteW     = advapi32.NewProc("CredWriteW")
	procCredDeleteW    = advapi32.NewProc("CredDeleteW")
	procCredEnumerateW = advapi32.NewProc("CredEnumerateW")
	procCredFree       = advapi32.NewProc("CredFree")
)

type winCred struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var errEntryNotFound = errors.New("entry not found")

func targetName(name string) string {
	return storePrefix + name
}

func stripPrefix(target string) string {
	return strings.TrimPrefix(target, storePrefix)
}

func utf16Ptr(s string) (*uint16, error) {
	return syscall.UTF16PtrFromString(s)
}

func utf16ToString(p *uint16) string {
	if p == nil {
		return ""
	}
	// Walk until null terminator
	n := 0
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) {
		n++
	}
	slice := unsafe.Slice(p, n)
	return syscall.UTF16ToString(slice)
}

// credWrite encrypts password with the active mode and stores it.
func credWrite(name, password string) error {
	blob, err := encryptEntry(name, password)
	if err != nil {
		return err
	}
	return credWriteRaw(name, blob)
}

// credWriteRaw stores an already encrypted blob as-is.
func credWriteRaw(name string, blob []byte) error {
	return credWriteTarget(targetName(name), blob)
}

// credWriteTarget stores a blob under a full credential target name.
func credWriteTarget(targetStr string, blob []byte) error {
	if len(blob) > maxBlobSize {
		return fmt.Errorf("entry exceeds Windows credential blob limit (%d bytes, of which %d are encryption overhead)", maxBlobSize, blobOverhead)
	}

	target, err := utf16Ptr(targetStr)
	if err != nil {
		return err
	}

	var blobPtr *byte
	if len(blob) > 0 {
		blobPtr = &blob[0]
	}

	cred := winCred{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     blobPtr,
		Persist:            credPersistLocalMachine,
	}

	ret, _, lastErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&cred)), 0)
	if ret == 0 {
		return fmt.Errorf("CredWriteW: %w", lastErr)
	}
	return nil
}

// credRead loads an entry and decrypts it.
func credRead(name string) (string, error) {
	blob, err := credReadRaw(name)
	if err != nil {
		return "", err
	}
	return decryptEntry(name, blob)
}

// credReadRaw returns the stored blob without decrypting it.
func credReadRaw(name string) ([]byte, error) {
	blob, err := credReadTarget(targetName(name))
	if errors.Is(err, errEntryNotFound) {
		return nil, fmt.Errorf("%w: %s", errEntryNotFound, name)
	}
	return blob, err
}

// credReadTarget reads a blob by full credential target name. A missing
// target returns errEntryNotFound.
func credReadTarget(targetStr string) ([]byte, error) {
	target, err := utf16Ptr(targetStr)
	if err != nil {
		return nil, err
	}

	var pcred *winCred
	ret, _, lastErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(target)),
		credTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if ret == 0 {
		if lastErr == syscall.ERROR_NOT_FOUND {
			return nil, errEntryNotFound
		}
		return nil, fmt.Errorf("CredReadW: %w", lastErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))

	if pcred.CredentialBlobSize == 0 {
		return nil, nil
	}
	// Copy: the buffer is owned by CredFree
	return append([]byte(nil), unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize)...), nil
}

func credDelete(name string) error {
	err := credDeleteTarget(targetName(name))
	if errors.Is(err, errEntryNotFound) {
		return fmt.Errorf("entry not found: %s", name)
	}
	return err
}

// credDeleteTarget deletes by full credential target name. A missing target
// returns errEntryNotFound.
func credDeleteTarget(targetStr string) error {
	target, err := utf16Ptr(targetStr)
	if err != nil {
		return err
	}

	ret, _, lastErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(target)),
		credTypeGeneric,
		0,
	)
	if ret == 0 {
		if lastErr == syscall.ERROR_NOT_FOUND {
			return errEntryNotFound
		}
		return fmt.Errorf("CredDeleteW: %w", lastErr)
	}
	return nil
}

func credEnumerate(filter string) ([]string, error) {
	searchFilter := storePrefix
	if filter != "" {
		searchFilter = storePrefix + filter
	}

	filterPtr, err := utf16Ptr(searchFilter + "*")
	if err != nil {
		return nil, err
	}

	var count uint32
	var pcreds uintptr

	ret, _, lastErr := procCredEnumerateW.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pcreds)),
	)
	if ret == 0 {
		if lastErr == syscall.ERROR_NOT_FOUND {
			return nil, nil
		}
		return nil, fmt.Errorf("CredEnumerateW: %w", lastErr)
	}
	defer procCredFree.Call(pcreds)

	credPtrs := unsafe.Slice((*uintptr)(unsafe.Pointer(pcreds)), count)
	names := make([]string, 0, count)
	for _, ptr := range credPtrs {
		cred := (*winCred)(unsafe.Pointer(ptr))
		target := utf16ToString(cred.TargetName)
		names = append(names, stripPrefix(target))
	}
	return names, nil
}
