package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const fallbackEditor = "notepad.exe"

// editorCommand resolves $EDITOR into a command and its arguments. The value
// is first tried as a single executable path (it may contain spaces), then
// split on whitespace to allow arguments such as "code --wait".
func editorCommand() (string, []string) {
	editor := strings.TrimSpace(os.Getenv("EDITOR"))
	if editor == "" {
		return fallbackEditor, nil
	}
	if _, err := exec.LookPath(editor); err == nil {
		return editor, nil
	}
	fields := strings.Fields(editor)
	return fields[0], fields[1:]
}

// wipeAndRemove overwrites a file with zeros before deleting it. This is
// best-effort: it does not defeat SSD wear levelling or filesystem journaling.
func wipeAndRemove(path string) {
	if info, err := os.Stat(path); err == nil {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			_, _ = f.Write(make([]byte, info.Size()))
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}

// editInTempFile writes initial to a temporary file, runs the editor on it and
// returns the edited content. The file is wiped afterwards.
func editInTempFile(initial string) (string, error) {
	f, err := os.CreateTemp("", "winpass-*.txt")
	if err != nil {
		return "", err
	}
	path := f.Name()
	defer wipeAndRemove(path)

	if _, err := f.WriteString(initial); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	editor, editorArgs := editorCommand()
	cmd := exec.Command(editor, append(editorArgs, path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("editor %q failed: %w", editor, err)
	}

	edited, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(edited), nil
}

func cmdEdit(args []string) error {
	opts, err := parseOptions(args, nil)
	if err != nil {
		return err
	}
	if len(opts.positional) != 1 {
		return fmt.Errorf("usage: winpass edit <name>")
	}
	name := opts.positional[0]

	current, err := credRead(name)
	isNew := errors.Is(err, errEntryNotFound)
	if err != nil && !isNew {
		return err
	}

	content := current
	for {
		edited, err := editInTempFile(content)
		if err != nil {
			return err
		}
		if !isNew && edited == current {
			fmt.Printf("Password for %s unchanged.\n", name)
			return nil
		}
		if edited == "" {
			fmt.Println("Empty content, nothing stored.")
			return nil
		}

		if err := credWrite(name, edited); err != nil {
			// Keep the edit in memory so a size error does not lose the user's work
			if confirm(fmt.Sprintf("Could not store %s: %v. Re-open the editor?", name, err)) {
				content = edited
				continue
			}
			return err
		}
		fmt.Printf("Password for %s stored.\n", name)
		return nil
	}
}
