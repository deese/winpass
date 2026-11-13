package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32                         = syscall.NewLazyDLL("user32.dll")
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormat    = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
	procGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	procGlobalLock                 = kernel32.NewProc("GlobalLock")
	procGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	procGlobalFree                 = kernel32.NewProc("GlobalFree")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	// Process creation flags used to detach the clipboard cleaner from the console
	detachedProcess    = 0x00000008
	createNewProcGroup = 0x00000200

	clearClipboardCmd = "__clear-clipboard"
	clipClearSeconds  = 45
)

// Clipboard formats that tell Windows clipboard history, cloud clipboard and
// clipboard monitors to ignore the content.
var historyOptOutFormats = []string{
	"ExcludeClipboardContentFromMonitorProcessing",
	"CanIncludeInClipboardHistory",
	"CanUploadToCloudClipboard",
}

// allocGlobal copies data into a new movable global memory block.
func allocGlobal(data []byte) (uintptr, error) {
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)))
	if h == 0 {
		return 0, fmt.Errorf("GlobalAlloc: %w", err)
	}
	ptr, _, err := procGlobalLock.Call(h)
	if ptr == 0 {
		procGlobalFree.Call(h)
		return 0, fmt.Errorf("GlobalLock: %w", err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(data)), data)
	procGlobalUnlock.Call(h)
	return h, nil
}

// setHistoryOptOut marks the current clipboard content as excluded from
// history/cloud sync. Must be called while the clipboard is open.
// Failures are ignored: these formats are best-effort hints.
func setHistoryOptOut() {
	// DWORD 0 for the "Can*" formats, DWORD 1 for the "Exclude*" format
	zero := []byte{0, 0, 0, 0}
	one := []byte{1, 0, 0, 0}
	for _, name := range historyOptOutFormats {
		namePtr, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		format, _, _ := procRegisterClipboardFormat.Call(uintptr(unsafe.Pointer(namePtr)))
		if format == 0 {
			continue
		}
		value := zero
		if name == historyOptOutFormats[0] {
			value = one
		}
		h, err := allocGlobal(value)
		if err != nil {
			continue
		}
		if ret, _, _ := procSetClipboardData.Call(format, h); ret == 0 {
			procGlobalFree.Call(h)
		}
	}
}

func copyToClipboard(text string) error {
	utf16, err := syscall.UTF16FromString(text)
	if err != nil {
		return err
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&utf16[0])), len(utf16)*2)
	h, err := allocGlobal(raw)
	if err != nil {
		return err
	}

	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("OpenClipboard: %w", err)
	}

	procEmptyClipboard.Call()
	ret, _, err = procSetClipboardData.Call(cfUnicodeText, h)
	if ret == 0 {
		procCloseClipboard.Call()
		procGlobalFree.Call(h)
		return fmt.Errorf("SetClipboardData: %w", err)
	}
	setHistoryOptOut()
	procCloseClipboard.Call()

	// Sequence number after our last write; the cleaner only clears if it is unchanged
	seq, _, _ := procGetClipboardSequenceNumber.Call()

	if err := spawnClipboardCleaner(clipClearSeconds, uint32(seq)); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not schedule clipboard clear: %v\n", err)
		return nil
	}
	fmt.Printf("Copied to clipboard. Will clear in %d seconds.\n", clipClearSeconds)
	return nil
}

// spawnClipboardCleaner starts a detached copy of this binary that outlives the
// current process. No secret is passed to it, only a clipboard sequence number.
func spawnClipboardCleaner(seconds int, seq uint32) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, clearClipboardCmd, strconv.Itoa(seconds), strconv.FormatUint(uint64(seq), 10))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNewProcGroup,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// cmdClearClipboard is the hidden entry point of the detached cleaner:
// __clear-clipboard <seconds> <sequence-number>
func cmdClearClipboard(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: winpass %s <seconds> <sequence>", clearClipboardCmd)
	}
	seconds, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid seconds: %s", args[0])
	}
	seq, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid sequence: %s", args[1])
	}

	time.Sleep(time.Duration(seconds) * time.Second)

	// Leave the clipboard alone if the user copied something else in the meantime
	current, _, _ := procGetClipboardSequenceNumber.Call()
	if uint32(current) != uint32(seq) {
		return nil
	}
	clearClipboard()
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
