package main

import (
	"fmt"
	"os"
)

// version is overridden at build time via -ldflags "-X main.version=<tag>"
var version = "dev"

const usage = `Usage: winpass <command> [args]

Commands:
  show <name>          Show password (optionally copy with -c)
  insert <name>        Insert new password
  generate <name> [n]  Generate password of length n (default 25)
  rm <name>            Remove entry
  mv <old> <new>       Rename entry
  cp <old> <new>       Copy entry
  ls [filter]          List entries
  find <term>          Search entries
  export <file>        Export all entries to an encrypted file
  import [-f] <file>   Import entries from an encrypted file (-f overwrites)
  help                 Show this help
  version              Show version

Flags:
  -c   Copy password to clipboard instead of printing
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "show":
		err = cmdShow(args)
	case "insert":
		err = cmdInsert(args)
	case "generate":
		err = cmdGenerate(args)
	case "rm", "remove":
		err = cmdRm(args)
	case "mv", "rename":
		err = cmdMv(args)
	case "cp", "copy":
		err = cmdCp(args)
	case "ls", "list":
		err = cmdLs(args)
	case "find", "search":
		err = cmdFind(args)
	case "export":
		err = cmdExport(args)
	case "import":
		err = cmdImport(args)
	case "help", "--help", "-h":
		fmt.Print(usage)
	case "version", "--version", "-v":
		fmt.Println("winpass", version)
	default:
		// bare name acts as show, like pass does
		err = cmdShow(os.Args[1:])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
