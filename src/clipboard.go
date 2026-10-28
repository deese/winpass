package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func copyToClipboard(text string) error {
	utf16, err := syscall.UTF16FromString(text)
	if err != nil {
		return err
	}
	size := uintptr(len(utf16) * 2)

	h, _, err := procGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return fmt.Errorf("GlobalAlloc: %w", err)
	}

	ptr, _, err := procGlobalLock.Call(h)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock: %w", err)
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16))
	copy(dst, utf16)
	procGlobalUnlock.Call(h)

	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return fmt.Errorf("OpenClipboard: %w", err)
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()
	ret, _, err = procSetClipboardData.Call(cfUnicodeText, h)
	if ret == 0 {
		return fmt.Errorf("SetClipboardData: %w", err)
	}

	fmt.Println("Copied to clipboard. Will clear in 45 seconds.")
	go func() {
		time.Sleep(45 * time.Second)
		clearClipboard()
	}()

	return nil
}

func clearClipboard() {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
}
