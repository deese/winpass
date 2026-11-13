package main

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// transferPair is one entry to copy or move.
type transferPair struct {
	src, dst string
}

// planTransfer resolves the entries affected by "mv/cp <oldArg> <newArg>" with
// the usual mv semantics: a trailing "/" on newArg, or an existing directory
// there, means "into that directory". names is the list of all stored entries.
func planTransfer(oldArg, newArg string, names []string) ([]transferPair, error) {
	exists := make(map[string]bool, len(names))
	for _, n := range names {
		exists[n] = true
	}
	hasChildren := func(dir string) bool {
		for _, n := range names {
			if strings.HasPrefix(n, dir+"/") {
				return true
			}
		}
		return false
	}

	old := strings.TrimSuffix(oldArg, "/")
	newTrim := strings.TrimSuffix(newArg, "/")
	if old == "" || newTrim == "" {
		return nil, fmt.Errorf("empty entry name")
	}
	intoDir := strings.HasSuffix(newArg, "/") || (hasChildren(newTrim) && !exists[newTrim])

	// A single entry
	if exists[old] {
		dst := newTrim
		if intoDir {
			dst = newTrim + "/" + path.Base(old)
		}
		if dst == old {
			return nil, fmt.Errorf("source and destination are the same: %s", old)
		}
		return []transferPair{{old, dst}}, nil
	}

	// A directory: every entry below old/
	var children []string
	for _, n := range names {
		if strings.HasPrefix(n, old+"/") {
			children = append(children, n)
		}
	}
	if len(children) == 0 {
		return nil, fmt.Errorf("%w: %s", errEntryNotFound, old)
	}
	sort.Strings(children)

	destBase := newTrim
	if intoDir {
		destBase = newTrim + "/" + path.Base(old)
	}
	if destBase == old {
		return nil, fmt.Errorf("source and destination are the same: %s", old)
	}
	if strings.HasPrefix(destBase, old+"/") {
		return nil, fmt.Errorf("cannot move or copy directory %s into itself", old)
	}
	pairs := make([]transferPair, 0, len(children))
	for _, c := range children {
		pairs = append(pairs, transferPair{c, destBase + strings.TrimPrefix(c, old)})
	}
	return pairs, nil
}

// transferEntries implements mv (move=true) and cp (move=false).
func transferEntries(cmd string, args []string, move bool) error {
	opts, err := parseOptions(args, []flagSpec{{short: 'f', long: "force"}})
	if err != nil {
		return err
	}
	if len(opts.positional) != 2 {
		return fmt.Errorf("usage: winpass %s [--force, -f] <old> <new>", cmd)
	}
	oldArg, newArg := opts.positional[0], opts.positional[1]

	names, err := credEnumerate("")
	if err != nil {
		return err
	}
	pairs, err := planTransfer(oldArg, newArg, names)
	if err != nil {
		return err
	}

	existing := make(map[string]bool, len(names))
	for _, n := range names {
		existing[n] = true
	}
	conflicts := 0
	conflictName := ""
	for _, p := range pairs {
		if existing[p.dst] {
			conflicts++
			conflictName = p.dst
		}
	}
	if conflicts > 0 && !opts.flags["force"] {
		prompt := fmt.Sprintf("An entry already exists for %s. Overwrite it?", conflictName)
		if conflicts > 1 {
			prompt = fmt.Sprintf("%d entries already exist at the destination. Overwrite them?", conflicts)
		}
		if !confirm(prompt) {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Write every destination first so a failure never loses an entry
	destinations := make(map[string]bool, len(pairs))
	for _, p := range pairs {
		value, err := credRead(p.src)
		if err != nil {
			return err
		}
		if err := credWrite(p.dst, value); err != nil {
			return err
		}
		destinations[p.dst] = true
	}
	if move {
		for _, p := range pairs {
			if destinations[p.src] {
				continue // overwritten by another pair, nothing to delete
			}
			if err := credDelete(p.src); err != nil {
				return err
			}
		}
	}

	verb := "Copied"
	if move {
		verb = "Moved"
	}
	if len(pairs) == 1 {
		fmt.Printf("%s %s to %s.\n", verb, pairs[0].src, pairs[0].dst)
		return nil
	}
	fmt.Printf("%s %d entries from %s to %s.\n", verb, len(pairs), oldArg, newArg)
	return nil
}
