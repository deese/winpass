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
| `show [-c] <name>` | Print password. `-c` copies to clipboard instead |
| `insert [-m] <name>` | Insert password interactively. `-m` for multiline |
| `generate [-c] [-n] <name> [length]` | Generate random password (default length: 25). `-c` copies, `-n` no symbols |
| `rm <name>` | Delete entry (prompts for confirmation) |
| `mv <old> <new>` | Rename entry |
| `cp <old> <new>` | Copy entry |
| `ls [filter]` | List all entries as a tree |
| `find <term>` | Search entries by name |
| `export <file>` | Export all entries to a passphrase-encrypted file (AES-256-GCM, PBKDF2-SHA256) |
| `import [-f] <file>` | Import entries from an export file. Existing entries are skipped unless `-f` is given |
| `version` | Print version |

A bare name with no subcommand acts as `show`:

```
winpass email/gmail
```

### Clipboard

The `-c` flag copies only the first line of the stored value (the password). The clipboard is cleared automatically after 45 seconds.

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
