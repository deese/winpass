package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func cmdShow(args []string) error {
	clip := false
	name := ""
	for _, a := range args {
		if a == "-c" {
			clip = true
		} else {
			name = a
		}
	}
	if name == "" {
		return fmt.Errorf("usage: winpass show [-c] <name>")
	}

	password, err := credRead(name)
	if err != nil {
		return err
	}

	if clip {
		return copyToClipboard(firstLine(password))
	}
	fmt.Println(password)
	return nil
}

func cmdInsert(args []string) error {
	multiline := false
	name := ""
	for _, a := range args {
		if a == "-m" || a == "--multiline" {
			multiline = true
		} else {
			name = a
		}
	}
	if name == "" {
		return fmt.Errorf("usage: winpass insert [-m] <name>")
	}

	var password string
	if multiline {
		fmt.Printf("Enter contents of %s (Ctrl+Z to finish on Windows):\n", name)
		buf := make([]byte, maxBlobSize)
		n, err := os.Stdin.Read(buf)
		if err != nil && n == 0 {
			return fmt.Errorf("read error: %w", err)
		}
		password = string(buf[:n])
	} else {
		fmt.Printf("Enter password for %s: ", name)
		p1, err := readPassword()
		if err != nil {
			return err
		}
		fmt.Printf("\nRetype password for %s: ", name)
		p2, err := readPassword()
		if err != nil {
			return err
		}
		fmt.Println()
		if p1 != p2 {
			return fmt.Errorf("passwords do not match")
		}
		password = p1
	}

	if err := credWrite(name, password); err != nil {
		return err
	}
	fmt.Printf("Password for %s stored.\n", name)
	return nil
}

func cmdGenerate(args []string) error {
	clip := false
	noSymbols := false
	name := ""
	length := defaultPasswordLength

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c":
			clip = true
		case "-n", "--no-symbols":
			noSymbols = true
		default:
			if name == "" {
				name = args[i]
			} else {
				n, err := strconv.Atoi(args[i])
				if err != nil {
					return fmt.Errorf("invalid length: %s", args[i])
				}
				length = n
			}
		}
	}
	if name == "" {
		return fmt.Errorf("usage: winpass generate [-c] [-n] <name> [length]")
	}
	_ = noSymbols // TODO: add alphanumeric-only charset when flag is set

	password, err := generatePassword(length)
	if err != nil {
		return err
	}
	if err := credWrite(name, password); err != nil {
		return err
	}

	if clip {
		fmt.Printf("Generated password for %s.\n", name)
		return copyToClipboard(password)
	}
	fmt.Printf("Generated password for %s: %s\n", name, password)
	return nil
}

func cmdRm(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: winpass rm <name>")
	}
	name := args[0]
	fmt.Printf("Are you sure you want to delete %s? [y/N] ", name)
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("Aborted.")
		return nil
	}
	if err := credDelete(name); err != nil {
		return err
	}
	fmt.Printf("Deleted %s.\n", name)
	return nil
}

func cmdMv(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: winpass mv <old> <new>")
	}
	old, newName := args[0], args[1]
	password, err := credRead(old)
	if err != nil {
		return err
	}
	if err := credWrite(newName, password); err != nil {
		return err
	}
	if err := credDelete(old); err != nil {
		return err
	}
	fmt.Printf("Renamed %s to %s.\n", old, newName)
	return nil
}

func cmdCp(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: winpass cp <old> <new>")
	}
	old, newName := args[0], args[1]
	password, err := credRead(old)
	if err != nil {
		return err
	}
	if err := credWrite(newName, password); err != nil {
		return err
	}
	fmt.Printf("Copied %s to %s.\n", old, newName)
	return nil
}

func cmdLs(args []string) error {
	filter := ""
	if len(args) > 0 {
		filter = args[0]
	}
	names, err := credEnumerate(filter)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Println("No passwords stored.")
		return nil
	}
	sort.Strings(names)
	fmt.Println("Password Store")
	printTree(names)
	return nil
}

func cmdFind(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: winpass find <term>")
	}
	term := strings.ToLower(args[0])
	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	var matches []string
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), term) {
			matches = append(matches, n)
		}
	}
	if len(matches) == 0 {
		fmt.Printf("No matches for %q.\n", term)
		return nil
	}
	sort.Strings(matches)
	fmt.Printf("Search results for %q:\n", args[0])
	for _, m := range matches {
		fmt.Printf("  %s\n", m)
	}
	return nil
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}

var (
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

func readPassword() (string, error) {
	handle, err := syscall.Open("CONIN$", syscall.O_RDWR, 0)
	if err != nil {
		var pw string
		fmt.Scanln(&pw)
		return pw, nil
	}
	defer syscall.Close(handle)

	var oldMode uint32
	procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&oldMode)))
	// Disable echo (ENABLE_ECHO_INPUT = 0x0004)
	procSetConsoleMode.Call(uintptr(handle), uintptr(oldMode&^uint32(0x0004)))
	defer procSetConsoleMode.Call(uintptr(handle), uintptr(oldMode))

	var pw string
	fmt.Scanln(&pw)
	return pw, nil
}

// printTree renders a tree view for a sorted list of slash-separated paths
func printTree(names []string) {
	type node struct {
		children map[string]*node
		isLeaf   bool
	}
	root := &node{children: make(map[string]*node)}

	for _, name := range names {
		parts := strings.Split(name, "/")
		cur := root
		for _, p := range parts {
			if cur.children[p] == nil {
				cur.children[p] = &node{children: make(map[string]*node)}
			}
			cur = cur.children[p]
		}
		cur.isLeaf = true
	}

	var walk func(n *node, prefix string)
	walk = func(n *node, prefix string) {
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			last := i == len(keys)-1
			connector := "├── "
			childPrefix := prefix + "│   "
			if last {
				connector = "└── "
				childPrefix = prefix + "    "
			}
			fmt.Printf("%s%s%s\n", prefix, connector, k)
			walk(n.children[k], childPrefix)
		}
	}
	walk(root, "")
}
