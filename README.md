# winpass

A drop-in replacement for [pass](https://www.passwordstore.org/) on Windows, backed by the Windows Credential Store (DPAPI).

Single binary, zero external dependencies.

## Installation

```
go build -ldflags="-s -w" -o winpass.exe .
```

Copy `winpass.exe` to any directory in your `PATH`.

## Usage

```
winpass <command> [args]
```

| Command | Description |
|---|---|
| `show [-c[line]] <name>` | Print password. `-c` copies the first (or given) line to the clipboard instead |
| `insert [-e \| -m] [-f] <name>` | Insert password interactively. `-e` echoes input, `-m` multiline, `-f` skips the overwrite prompt |
| `generate [-c] [-n] [-i \| -f] <name> [length]` | Generate random password (default length: 25). `-c` copies, `-n` no symbols, `-i` replaces only the first line of an existing entry, `-f` skips the overwrite prompt |
| `rm [-r] [-f] <name>` | Delete entry. `-r` deletes a directory recursively, `-f` skips the confirmation |
| `mv [-f] <old> <new>` | Rename entry. Prompts before overwriting unless `-f` |
| `cp [-f] <old> <new>` | Copy entry. Prompts before overwriting unless `-f` |
| `ls [filter]` | List all entries as a tree |
| `find <term>` | Search entries by name |
| `export <file>` | Export all entries to a passphrase-encrypted file (AES-256-GCM, PBKDF2-SHA256) |
| `import [-f] <file>` | Import entries from an export file. Existing entries are skipped unless `-f` is given |
| `completion powershell` | Print the PowerShell tab-completion script |
| `version` | Print version |

A bare name with no subcommand acts as `show`:

```
winpass email/gmail
```

### Clipboard

The `-c` flag copies only the first line of the stored value (the password), or line N with `-cN`. The clipboard is cleared automatically after 45 seconds (`PASSWORD_STORE_CLIP_TIME`), by a detached copy of `winpass.exe`. The clear is skipped if you copied something else in the meantime. The copied value is flagged to be excluded from Windows clipboard history and the cloud clipboard.

### Environment variables

| Variable | Description |
|---|---|
| `PASSWORD_STORE_CLIP_TIME` | Seconds before the clipboard is cleared (default: 45) |
| `PASSWORD_STORE_GENERATED_LENGTH` | Default length for `generate` (default: 25) |
| `PASSWORD_STORE_CHARACTER_SET` | Characters used by `generate`. Literal characters only, `tr` classes such as `[:alnum:]` are not supported |
| `PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS` | Same, used with `-n` |

### PowerShell tab completion

Paste the output of `winpass completion powershell` into your `$PROFILE`. It works in Constrained Language Mode and completes subcommands and entry names. Entry names are read from the credential store; values are never decrypted for completion.

### Hierarchy

Entries are organized with `/` as a path separator, mirroring pass's directory structure:

```
winpass insert email/gmail
winpass insert email/work
winpass insert infra/aws/root
winpass ls
```

```
Password Store
└── email
│   ├── gmail
│   └── work
└── infra
    └── aws
        └── root
```

## Storage

Credentials are stored as generic credentials in the Windows Credential Manager under the prefix `winpass/`. You can view and manage them in **Control Panel → Credential Manager → Windows Credentials**.

Each entry is encrypted with DPAPI, scoped to the current Windows user account.

## Limitations

- **2560-byte blob limit** — the Windows Credential Store caps credential blobs at 2560 bytes. Entries exceeding this limit are rejected with an explicit error.
- **No cross-machine sync** — DPAPI encryption is tied to the local user and machine. There is no equivalent to pass's git backend.
- **No GPG** — encryption is handled entirely by DPAPI; there is no GPG key management.

## Differences from pass

| Feature | pass | winpass |
|---|---|---|
| Encryption | GPG | DPAPI (Windows Credential Store) |
| Sync | git | None (local only) |
| Multiline entries | Unlimited size | 2560 bytes max |
| Platform | Unix | Windows |
| Dependencies | gpg, git, bash | None |
| Extensions | yes | Not planned (I don't have a use-case yet) | 

## Building from source

Requires Go 1.21+. No external modules.

```
git clone <repo>
cd winpass
go build -ldflags="-s -w" -o winpass.exe .
```
