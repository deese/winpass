package main

import (
	"fmt"
	"os"
	"strings"
)

// version is overridden at build time via -ldflags "-X main.version=<tag>"
var version = "dev"

const usage = `Usage: winpass <command> [args]

Commands:
  show <name>             Show password (optionally copy with -c)
  insert <name>           Insert new password
  edit <name>             Edit an entry with $EDITOR (default: notepad)
  generate <name> [n]     Generate password of length n (default 25)
  rm <name>               Remove entry
  mv <old> <new>          Rename entry
  cp <old> <new>          Copy entry
  ls [filter]             List entries
  find <term>...          Search entries by name
  grep [-i] <regex>       Search inside decrypted entries
  export <file>           Export all entries to an encrypted file
  import [-f] <file>      Import entries from an encrypted file (-f overwrites)
  status                  Show the active key mode and how entries are stored
  setup keyfile [path]    Create a keyfile used as encryption key (--remove deletes it)
  setup tpm               Create a TPM-backed key (--remove deletes it)
  verify <file> [<name>]  Check an export against the store; with a name, show or copy (-c) that entry
  migrate [--to <mode>]   Re-encrypt all entries with a key mode (--skip-backup skips the prompt)
  init                    No-op, kept for pass compatibility
  completion powershell   Print the PowerShell tab-completion script
  help                    Show this help
  version                 Show version

Flags:
  -c   Copy password to clipboard instead of printing
`

// commandAliases maps alternative command names to the name used in usage.
var commandAliases = map[string]string{
	"remove": "rm",
	"rename": "mv",
	"copy":   "cp",
	"list":   "ls",
	"search": "find",
}

// wantsHelp reports whether args ask for command help. Anything after "--"
// is a positional argument and is ignored.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}

// commandHelp returns the usage lines of a command, none if it has no entry.
func commandHelp(cmd string) []string {
	if canonical, ok := commandAliases[cmd]; ok {
		cmd = canonical
	}
	var lines []string
	for _, line := range strings.Split(usage, "\n") {
		fields := strings.Fields(line)
		if strings.HasPrefix(line, "  ") && len(fields) > 0 && fields[0] == cmd {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	if wantsHelp(args) {
		if lines := commandHelp(cmd); len(lines) > 0 {
			for _, line := range lines {
				fmt.Println("winpass " + line)
			}
			return
		}
	}

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
	case "status":
		err = cmdStatus(args)
	case "setup":
		err = cmdSetup(args)
	case "verify":
		err = cmdVerify(args)
	case "migrate":
		err = cmdMigrate(args)
	case "edit":
		err = cmdEdit(args)
	case "grep":
		err = cmdGrep(args)
	case "init":
		// pass compatibility: there is no store to initialize, so scripts calling init keep working
		fmt.Fprintln(os.Stderr, "winpass: init is not needed, entries are encrypted automatically. See 'winpass status' and 'winpass setup'. Nothing to do.")
	case completeCmd:
		err = cmdComplete(args)
	case "completion":
		err = cmdCompletion(args)
	case clearClipboardCmd:
		err = cmdClearClipboard(args)
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
