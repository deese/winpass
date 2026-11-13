package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func cmdShow(args []string) error {
	opts, err := parseOptions(args, []flagSpec{{short: 'c', long: "clip", optValue: true}})
	if err != nil {
		return err
	}
	if len(opts.positional) != 1 {
		return fmt.Errorf("usage: winpass show [--clip[=line], -c[line]] <name>")
	}
	name := opts.positional[0]

	password, err := credRead(name)
	if err != nil {
		return err
	}

	if opts.flags["clip"] {
		line := opts.values["clip"]
		if line == 0 {
			line = 1
		}
		text, ok := nthLine(password, line)
		if !ok {
			return fmt.Errorf("there is no line %d in %s", line, name)
		}
		return copyToClipboard(text)
	}
	fmt.Println(password)
	return nil
}

// entryExists reports whether an entry is stored under name.
func entryExists(name string) (bool, error) {
	_, err := credRead(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errEntryNotFound) {
		return false, nil
	}
	return false, err
}

// confirm asks a yes/no question on stdout and reads the answer from stdin.
func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	answer, _ := readLine()
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}

// confirmOverwrite returns true if name does not exist, force is set, or the
// user agrees to overwrite it.
func confirmOverwrite(name string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	exists, err := entryExists(name)
	if err != nil || !exists {
		return true, err
	}
	return confirm(fmt.Sprintf("An entry already exists for %s. Overwrite it?", name)), nil
}

func cmdInsert(args []string) error {
	opts, err := parseOptions(args, []flagSpec{
		{short: 'm', long: "multiline"},
		{short: 'e', long: "echo"},
		{short: 'f', long: "force"},
	})
	if err != nil {
		return err
	}
	if len(opts.positional) != 1 {
		return fmt.Errorf("usage: winpass insert [--echo, -e | --multiline, -m] [--force, -f] <name>")
	}
	name := opts.positional[0]
	if opts.flags["multiline"] && opts.flags["echo"] {
		return fmt.Errorf("--echo and --multiline cannot be combined")
	}

	ok, err := confirmOverwrite(name, opts.flags["force"])
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("Aborted.")
		return nil
	}

	var password string
	if opts.flags["echo"] {
		fmt.Printf("Enter password for %s: ", name)
		password, err = readLine()
		if err != nil {
			return err
		}
	} else if opts.flags["multiline"] {
		fmt.Printf("Enter contents of %s (Ctrl+Z to finish on Windows):\n", name)
		// Read until EOF; one byte over the limit is enough to detect oversized input
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxBlobSize+1))
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}
		if len(data) > maxBlobSize {
			return fmt.Errorf("input exceeds Windows credential blob limit (%d bytes)", maxBlobSize)
		}
		password = string(data)
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
	opts, err := parseOptions(args, []flagSpec{
		{short: 'c', long: "clip"},
		{short: 'n', long: "no-symbols"},
		{short: 'i', long: "in-place"},
		{short: 'f', long: "force"},
	})
	if err != nil {
		return err
	}
	const usage = "usage: winpass generate [--no-symbols, -n] [--clip, -c] [--in-place, -i | --force, -f] <name> [length]"
	if len(opts.positional) < 1 || len(opts.positional) > 2 {
		return fmt.Errorf(usage)
	}
	if opts.flags["in-place"] && opts.flags["force"] {
		return fmt.Errorf("--in-place and --force cannot be combined")
	}
	name := opts.positional[0]
	clip := opts.flags["clip"]
	inPlace := opts.flags["in-place"]

	length, err := envPositiveInt(envGeneratedLength, defaultPasswordLength)
	if err != nil {
		return err
	}
	if len(opts.positional) == 2 {
		n, err := strconv.Atoi(opts.positional[1])
		if err != nil || n < 1 {
			return fmt.Errorf("invalid length: %s", opts.positional[1])
		}
		length = n
	}

	// In-place keeps everything after the first line of the existing entry
	rest := ""
	if inPlace {
		existing, err := credRead(name)
		if err != nil {
			return err
		}
		if idx := strings.IndexByte(existing, '\n'); idx >= 0 {
			rest = existing[idx:]
		}
	} else {
		ok, err := confirmOverwrite(name, opts.flags["force"])
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Aborted.")
			return nil
		}
	}

	password, err := generatePassword(length, !opts.flags["no-symbols"])
	if err != nil {
		return err
	}
	if err := credWrite(name, password+rest); err != nil {
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
	opts, err := parseOptions(args, []flagSpec{
		{short: 'r', long: "recursive"},
		{short: 'f', long: "force"},
	})
	if err != nil {
		return err
	}
	if len(opts.positional) != 1 {
		return fmt.Errorf("usage: winpass rm [--recursive, -r] [--force, -f] <name>")
	}
	name := strings.TrimSuffix(opts.positional[0], "/")
	force := opts.flags["force"]

	// Entries to delete: the exact entry and, with -r, everything below name/
	exists, err := entryExists(name)
	if err != nil {
		return err
	}
	var targets []string
	if exists {
		targets = append(targets, name)
	}
	children, err := credEnumerate(name + "/")
	if err != nil {
		return err
	}
	sort.Strings(children)
	if len(children) > 0 {
		if !opts.flags["recursive"] {
			return fmt.Errorf("%s is a directory, use -r to delete it recursively", name)
		}
		targets = append(targets, children...)
	}
	if len(targets) == 0 {
		return fmt.Errorf("%w: %s", errEntryNotFound, name)
	}

	if !force {
		prompt := fmt.Sprintf("Are you sure you want to delete %s?", name)
		if len(children) > 0 {
			prompt = fmt.Sprintf("Are you sure you want to delete %s and its %d entries below it?", name, len(children))
		}
		if !confirm(prompt) {
			fmt.Println("Aborted.")
			return nil
		}
	}
	for _, t := range targets {
		if err := credDelete(t); err != nil {
			return err
		}
		fmt.Printf("Deleted %s.\n", t)
	}
	return nil
}

func cmdMv(args []string) error {
	return transferEntries("mv", args, true)
}

func cmdCp(args []string) error {
	return transferEntries("cp", args, false)
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
		return fmt.Errorf("usage: winpass find <term>...")
	}
	terms := make([]string, len(args))
	for i, a := range args {
		terms[i] = strings.ToLower(a)
	}
	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	// An entry matches when its name contains any of the terms, like pass
	var matches []string
	for _, n := range names {
		lower := strings.ToLower(n)
		for _, term := range terms {
			if strings.Contains(lower, term) {
				matches = append(matches, n)
				break
			}
		}
	}
	label := strings.Join(args, "|")
	if len(matches) == 0 {
		fmt.Printf("No matches for %q.\n", label)
		return nil
	}
	sort.Strings(matches)
	fmt.Printf("Search results for %q:\n", label)
	for _, m := range matches {
		fmt.Printf("  %s\n", m)
	}
	return nil
}

// cmdGrep prints, for every entry, the decrypted lines matching a regular
// expression. Matching lines are printed as-is, including the password line.
func cmdGrep(args []string) error {
	opts, err := parseOptions(args, []flagSpec{{short: 'i', long: "ignore-case"}})
	if err != nil {
		return err
	}
	if len(opts.positional) != 1 {
		return fmt.Errorf("usage: winpass grep [--ignore-case, -i] <regex>")
	}
	pattern := opts.positional[0]
	if opts.flags["ignore-case"] {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}

	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		content, err := credRead(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", name, err)
			continue
		}
		var hits []string
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSuffix(line, "\r")
			if re.MatchString(line) {
				hits = append(hits, line)
			}
		}
		if len(hits) == 0 {
			continue
		}
		fmt.Printf("%s:\n", name)
		for _, h := range hits {
			fmt.Println(h)
		}
	}
	return nil
}

// nthLine returns the 1-based line n of s without its line terminator.
func nthLine(s string, n int) (string, bool) {
	lines := strings.Split(s, "\n")
	if n < 1 || n > len(lines) {
		return "", false
	}
	return strings.TrimSuffix(lines[n-1], "\r"), true
}

var (
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

func readPassword() (string, error) {
	handle, err := syscall.Open("CONIN$", syscall.O_RDWR, 0)
	if err != nil {
		return readLine()
	}
	defer syscall.Close(handle)

	var oldMode uint32
	procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&oldMode)))
	// Disable echo (ENABLE_ECHO_INPUT = 0x0004)
	procSetConsoleMode.Call(uintptr(handle), uintptr(oldMode&^uint32(0x0004)))
	defer procSetConsoleMode.Call(uintptr(handle), uintptr(oldMode))

	return readLine()
}

// readLine reads a full line from stdin, keeping spaces. It reads byte by byte
// without buffering so consecutive prompts do not lose piped input.
func readLine() (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		if err != nil {
			if len(line) == 0 && err != io.EOF {
				return "", err
			}
			break
		}
	}
	return strings.TrimSuffix(string(line), "\r"), nil
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
