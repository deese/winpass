package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	machineEnvKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	userEnvKey    = `Environment`
	regExpandSZ   = 2 // REG_EXPAND_SZ
)

var procExpandEnvironmentStrings = kernel32.NewProc("ExpandEnvironmentStringsW")

// expandEnv expands %VAR% references using the current process environment.
func expandEnv(s string) string {
	src, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return s
	}
	size, _, _ := procExpandEnvironmentStrings.Call(uintptr(unsafe.Pointer(src)), 0, 0)
	if size == 0 {
		return s
	}
	buf := make([]uint16, size)
	n, _, _ := procExpandEnvironmentStrings.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(&buf[0])), size)
	if n == 0 || n > size {
		return s
	}
	return syscall.UTF16ToString(buf)
}

// readRegistryPath returns the persistent Path value stored under root\subkey,
// or "" if it cannot be read. REG_EXPAND_SZ values are expanded.
func readRegistryPath(root syscall.Handle, subkey string) string {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return ""
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(root, subkeyPtr, 0, syscall.KEY_QUERY_VALUE, &key); err != nil {
		return ""
	}
	defer func() { _ = syscall.RegCloseKey(key) }()

	name, _ := syscall.UTF16PtrFromString("Path")
	var valueType, size uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &valueType, nil, &size); err != nil || size == 0 {
		return ""
	}
	buf := make([]uint16, size/2+1)
	size = uint32(len(buf) * 2)
	if err := syscall.RegQueryValueEx(key, name, nil, &valueType, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return ""
	}
	value := syscall.UTF16ToString(buf)
	if valueType == regExpandSZ {
		value = expandEnv(value)
	}
	return value
}

// persistentPath returns the machine and user Path as stored in the registry,
// in the order Windows builds them for a new session (machine first).
func persistentPath() string {
	return mergePath(
		readRegistryPath(syscall.HKEY_LOCAL_MACHINE, machineEnvKey),
		readRegistryPath(syscall.HKEY_CURRENT_USER, userEnvKey),
	)
}

// mergePath joins PATH lists, keeping the first occurrence of each directory
// (case-insensitive) so earlier lists keep precedence.
func mergePath(lists ...string) string {
	seen := map[string]bool{}
	var dirs []string
	for _, list := range lists {
		for _, dir := range strings.Split(list, string(filepath.ListSeparator)) {
			// A stray quote (e.g. `C:\Program Files\PuTTY"`) makes Go's PATH
			// search swallow every entry after it, so quotes are dropped.
			dir = strings.TrimSpace(strings.ReplaceAll(dir, `"`, ""))
			key := strings.ToLower(strings.TrimRight(dir, `\/`))
			if dir == "" || seen[key] {
				continue
			}
			seen[key] = true
			dirs = append(dirs, dir)
		}
	}
	return strings.Join(dirs, string(filepath.ListSeparator))
}
