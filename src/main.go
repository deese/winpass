package main

import (
	"fmt"
	"os"
	"strings"
)

// version is overridden at build time via -ldflags "-X main.version=<tag>"
var version = "dev"

// commandDoc documents one form of a command. A command with several forms
// has one entry per form. Long option names are in parentheses.
type commandDoc struct {
	syntax string
	desc   string
}

var commandDocs = []commandDoc{
	{"show [-c[N]] <name>", "Show a password; -c (--clip) copies line N (default 1) to the clipboard instead"},
	{"insert [-e | -m] [-f] <name>", "Insert a password; -e (--echo) echoes input, -m (--multiline) reads several lines, -f (--force) overwrites"},
	{"edit <name>", "Edit an entry with $EDITOR (default: notepad)"},
	{"generate [-n] [-c] [-i | -f] <name> [n]", "Generate a password of length n (default 25); -n (--no-symbols), -c (--clip), -i (--in-place) replaces only the first line, -f (--force) overwrites"},
	{"rm [-r] [-f] <name>", "Remove an entry; -r (--recursive) removes a directory, -f (--force) skips the prompt"},
	{"mv [-f] <old> <new>", "Rename or move an entry or directory; -f (--force) overwrites"},
	{"cp [-f] <old> <new>", "Copy an entry or directory; -f (--force) overwrites"},
	{"ls [filter]", "List entries"},
	{"find <term>...", "Search entries by name"},
	{"grep [-i] <regex>", "Search inside decrypted entries; -i (--ignore-case)"},
	{"export <file>", "Export all entries to a passphrase-encrypted file"},
	{"import [-f] <file>", "Import entries from an export file; -f (--force) overwrites existing ones"},
	{"verify <file> [<name> [-c[N]]]", "Check an export against the store; with a name, print that entry or copy it with -c (--clip)"},
	{"status", "Show the active key mode and how entries are stored"},
	{"migrate [--to <mode>] [--skip-backup]", "Re-encrypt all entries; mode is default, keyfile or tpm; --skip-backup skips the backup prompt"},
	{"setup keyfile [path]", "Create a keyfile and use it as the encryption key"},
	{"setup keyfile --remove [--force] [path]", "Delete the keyfile; refuses while entries use it unless --force"},
	{"setup tpm", "Create a TPM-backed key"},
	{"setup tpm --remove [--force]", "Delete the TPM key; refuses while entries use it unless --force"},
	{"init", "No-op, kept for pass compatibility"},
	{"completion powershell", "Print the PowerShell tab-completion script"},
	{"help", "Show this help"},
	{"version", "Show version"},
}

// formatDocs aligns syntax and description in two columns.
func formatDocs(docs []commandDoc) []string {
	width := 0
	for _, d := range docs {
		width = max(width, len(d.syntax))
	}
	lines := make([]string, 0, len(docs))
	for _, d := range docs {
		lines = append(lines, fmt.Sprintf("%-*s  %s", width, d.syntax, d.desc))
	}
	return lines
}

func buildUsage() string {
	var b strings.Builder
	b.WriteString("Usage: winpass <command> [args]\n\nCommands:\n")
	for _, line := range formatDocs(commandDocs) {
		b.WriteString("  " + line + "\n")
	}
	return b.String()
}

var usage = buildUsage()

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
	var forms []commandDoc
	for _, d := range commandDocs {
		if strings.Fields(d.syntax)[0] == cmd {
			forms = append(forms, d)
		}
	}
	return formatDocs(forms)
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
