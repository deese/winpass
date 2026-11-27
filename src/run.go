package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
)

const runUsage = "usage: winpass run -e VAR=<name> [-e VAR=<name>]... -- <command> [args...]"

// envBinding maps an environment variable to the entry that provides its value.
type envBinding struct {
	variable string
	entry    string
}

// parseRunArgs splits run arguments into env bindings and the command to run.
// The "--" separator is mandatory so the command line is never ambiguous.
func parseRunArgs(args []string) ([]envBinding, []string, error) {
	var bindings []envBinding
	seen := map[string]bool{}

	addBinding := func(spec string) error {
		variable, entry, ok := strings.Cut(spec, "=")
		if !ok || variable == "" || entry == "" {
			return fmt.Errorf("invalid binding %q, expected VAR=<name>", spec)
		}
		if strings.ContainsRune(variable, 0) {
			return fmt.Errorf("invalid variable name %q", variable)
		}
		key := strings.ToUpper(variable) // Windows environment names are case-insensitive
		if seen[key] {
			return fmt.Errorf("variable %s is set more than once", variable)
		}
		seen[key] = true
		bindings = append(bindings, envBinding{variable: variable, entry: entry})
		return nil
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			command := args[i+1:]
			if len(command) == 0 {
				return nil, nil, errors.New("no command given after --")
			}
			if len(bindings) == 0 {
				return nil, nil, errors.New("at least one -e VAR=<name> is required")
			}
			return bindings, command, nil
		case a == "-e" || a == "--env":
			i++
			if i >= len(args) {
				return nil, nil, fmt.Errorf("option %s requires a VAR=<name> value", a)
			}
			if err := addBinding(args[i]); err != nil {
				return nil, nil, err
			}
		case strings.HasPrefix(a, "--env="):
			if err := addBinding(strings.TrimPrefix(a, "--env=")); err != nil {
				return nil, nil, err
			}
		case strings.HasPrefix(a, "-e") && !strings.HasPrefix(a, "--"):
			if err := addBinding(a[2:]); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unexpected argument %q before --", a)
		}
	}
	return nil, nil, errors.New(runUsage)
}

// mergeEnv returns base with the overrides applied. Existing variables are
// replaced case-insensitively, as Windows treats names.
func mergeEnv(base []string, overrides map[string]string) []string {
	upper := make(map[string]bool, len(overrides))
	for k := range overrides {
		upper[strings.ToUpper(k)] = true
	}
	merged := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		// A leading "=" marks Windows drive-cwd variables such as "=C:", keep them
		if name != "" && upper[strings.ToUpper(name)] {
			continue
		}
		merged = append(merged, kv)
	}
	for k, v := range overrides {
		merged = append(merged, k+"="+v)
	}
	return merged
}

// cmdRun decrypts the requested entries and starts a command with them as
// environment variables. Only the first line of each entry is used, and
// secrets never touch the command line, the clipboard or the disk.
func cmdRun(args []string) error {
	bindings, command, err := parseRunArgs(args)
	if err != nil {
		return err
	}

	// Resolve every secret before starting anything so a failure leaves no half-run
	overrides := make(map[string]string, len(bindings))
	for _, b := range bindings {
		content, err := credRead(b.entry)
		if err != nil {
			return err
		}
		value, _ := nthLine(content, 1)
		overrides[b.variable] = value
	}

	// Hosts such as Claude Desktop start us with a trimmed PATH. Append the
	// persistent one (current entries keep precedence) so the command and the
	// tools it spawns can be found.
	_, inheritedErr := exec.LookPath(command[0])
	if err := os.Setenv("PATH", mergePath(os.Getenv("PATH"), persistentPath())); err != nil {
		return fmt.Errorf("cannot update PATH: %w", err)
	}
	resolved, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("cannot run %q: %w", command[0], err)
	}
	if inheritedErr != nil {
		fmt.Fprintf(os.Stderr, "winpass: %s not in the inherited PATH, using %s\n", command[0], resolved)
	}

	cmd := exec.Command(resolved, command[1:]...)
	cmd.Env = mergeEnv(os.Environ(), overrides)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	// Ctrl+C reaches the child through the shared console; stay alive to relay its exit code
	signal.Ignore(os.Interrupt)

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("cannot run %q: %w", command[0], err)
	}
	return nil
}
