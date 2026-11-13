package main

import (
	_ "embed"
	"fmt"
	"sort"
)

//go:embed completion.ps1
var powershellCompletion string

const completeCmd = "__complete"

// cmdComplete prints stored entry names starting with the given prefix, one per
// line, for shell completion. It never reads or decrypts credential values.
func cmdComplete(args []string) error {
	prefix := ""
	if len(args) > 0 {
		prefix = args[0]
	}
	names, err := credEnumerate(prefix)
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func cmdCompletion(args []string) error {
	if len(args) != 1 || args[0] != "powershell" {
		return fmt.Errorf("usage: winpass completion powershell")
	}
	fmt.Print(powershellCompletion)
	return nil
}
