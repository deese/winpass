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
| `edit <name>` | Edit an entry with `$EDITOR` (default: `notepad.exe`). See the note below |
| `mv [-f] <old> <new>` | Rename or move an entry or a whole directory. A trailing `/` or an existing directory as destination means "into it". Prompts before overwriting unless `-f` |
| `cp [-f] <old> <new>` | Same as `mv`, but copies |
| `ls [filter]` | List all entries as a tree |
| `find <term>...` | Search entries by name. An entry matches if it contains any of the terms |
| `grep [-i] <regex>` | Search inside decrypted entries (Go RE2 syntax, not grep's). Prints matching lines, including the password line if it matches |
| `init` | No-op, kept so scripts written for pass do not fail |
| `export <file>` | Export all entries to a passphrase-encrypted file (AES-256-GCM, PBKDF2-SHA256) |
| `import [-f] <file>` | Import entries from an export file. Existing entries are skipped unless `-f` is given |
| `verify <file> [<name>] [-c[line]]` | Check an export file without importing it: asks for the passphrase, authenticates the file and compares it with the store without printing any value. With a name, prints that entry (or copies it with `-c`), which also works as a recovery path. Exits with 1 if the backup does not fully cover the current store |
| `status` | Show the active key mode, whether the keyfile and the TPM key exist, and how many entries use each mode. It reads headers only and never decrypts |
| `migrate [--to default\|keyfile\|tpm] [--skip-backup]` | Re-encrypt every entry with a key mode (default: the active one). Asks you to confirm a recent backup unless `--skip-backup`. Safe to re-run |
| `setup keyfile [path]` | Create a keyfile and use it as the encryption key. `--remove [--force]` deletes it, see [Key modes](#key-modes) |
| `setup tpm` | Create a TPM-backed key. `--remove [--force]` deletes it |
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
| `WINPASS_KEYFILE` | Path of the keyfile. Default: `%LOCALAPPDATA%\winpass\winpass.kf`. If set, the file must exist |

Every command also accepts `--help` (or `-h`) and prints its usage line.

### PowerShell tab completion

Paste the output of `winpass completion powershell` into your `$PROFILE`. It works in Constrained Language Mode and completes subcommands and entry names. Entry names are read from the credential store; values are never decrypted for completion.

### Editing

`edit` writes the entry to a temporary file in `%TEMP%`, runs `$EDITOR` and stores the result. The temporary file is overwritten with zeros and deleted afterwards. This is best-effort only: it does not defeat SSD wear levelling or filesystem journaling, so the plaintext may remain recoverable from disk. `$EDITOR` may include arguments (for example `code --wait`), and the editor must block until the file is closed.

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

Each entry has two layers. The Credential Manager encrypts the blob with DPAPI, scoped to the current Windows user account. On top of that, winpass seals the value with AES-256-GCM under a key whose source depends on the [key mode](#key-modes). The blob layout is `magic | mode | key ID | nonce | ciphertext`. The header and the entry name are authenticated, so a ciphertext cannot be moved to another entry or have its mode rewritten without detection.

Entries written by older versions are stored without the AES layer. They are still readable, with a warning, until you run `winpass migrate`.

## Key modes

DPAPI alone lets any process running as your user read every entry through `CredRead`. The key modes add a second secret that such a process does not get just by being your user.

| Mode | Key source | Set up with |
|---|---|---|
| `default` | HKDF of the machine's `MachineGuid` and a pepper compiled into the binary | nothing, it is the default |
| `keyfile` | A random 32-byte file | `winpass setup keyfile` |
| `tpm` | A non-exportable RSA key inside the TPM, used to sign a fixed challenge deterministically | `winpass setup tpm` |

New entries use the first available mode in this order: keyfile, tpm, default. Reading an entry uses whatever mode its header names, so a store can hold a mix, and `winpass migrate [--to <mode>]` converts everything. Run `winpass status` to see what is active and how many entries use each mode.

### What this protects against

The goal is to push back simple attacks, not to replace a vault such as 1Password. The modes help against tools that dump or bulk-read the Credential Manager without knowing winpass, and against blobs exfiltrated without the machine, the keyfile or the TPM.

They do not protect against an attacker who runs code as your user and knows winpass: that process can run `winpass` itself, read the keyfile, or ask the TPM to sign. The repository is public, so the `default` pepper is not a secret. The `default` key rests on the `MachineGuid` not travelling with the blob, and the `MachineGuid` is readable by any local process.

### Keyfile

`winpass setup keyfile [path]` creates 32 random bytes and never overwrites an existing file. Back it up offline and apart from your exports: without it, every entry encrypted with it is lost. The default location is under `%LOCALAPPDATA%` (not `%APPDATA%`, which can roam with a domain profile). Point `WINPASS_KEYFILE` at a USB stick or a share mounted on demand if you want the key absent most of the time.

If `WINPASS_KEYFILE` is set but the file does not exist, writing fails instead of falling back to the default mode, so a typo cannot silently downgrade new entries. If it is not set and the default file is missing, winpass uses the next mode. That fallback is silent: if you delete the keyfile, new entries go to `default` until you notice. `winpass status` shows it.

`winpass setup keyfile --remove` counts the entries encrypted with that file by reading headers and refuses while any exist. Run `winpass migrate --to default` (or `--to tpm`) first. `--force` is for the case where those entries are already lost.

### TPM

`winpass setup tpm` creates a persistent RSA-2048 key in the Microsoft Platform Crypto Provider, for the current user, and checks that two signatures of the challenge are identical, since the scheme depends on PKCS#1 v1.5 being deterministic. Nothing else is stored. A marker in the Credential Manager records that TPM mode is enabled, so ordinary commands do not open the TPM to find out.

Costs and risks:

- Every command that reads or writes a TPM-encrypted entry waits for the TPM. In testing on one machine, a read took roughly 0.4 to 0.55 seconds more than a `default` read. Measure it on yours. Commands that do not decrypt (`ls`, `find`, completion) are unaffected, and `status` pays only the cost of opening the TPM provider.
- If the TPM is cleared, replaced or reset, the key is gone and so are the entries encrypted with it. Keep an export.
- The key is per Windows user and per machine. It does not sync.
- If the marker is set but the key is missing, writes fail with an explicit error. `winpass setup tpm --remove` clears the marker; `winpass setup tpm` creates a new key.

`winpass setup tpm --remove` refuses while TPM-encrypted entries exist, like the keyfile. Run `winpass migrate --to default` first.

### Backups and recovery

`export` does not use any of the keys above. It asks for a passphrase at that moment and encrypts with PBKDF2-SHA256 and AES-256-GCM, so a backup stays readable if you lose a keyfile or clear the TPM. Check one with `winpass verify <file>`, and pull a single entry out of it with `winpass verify <file> <name>`.

Take an export before `migrate` and before removing a key.

## Limitations

- **2560-byte blob limit** — the Windows Credential Store caps credential blobs at 2560 bytes. The encryption layer adds 37 bytes, so an entry can hold at most 2523 bytes. Entries exceeding this limit are rejected with an explicit error.
- **No cross-machine sync** — DPAPI encryption is tied to the local user and machine. There is no equivalent to pass's git backend. Use `export` and `import` to move entries.
- **No GPG** — encryption is handled entirely by DPAPI and the key modes; there is no GPG key management.
- **Older binaries cannot read migrated entries** — once an entry has the AES layer, a winpass version without it returns unreadable bytes.

## Differences from pass

| Feature | pass | winpass |
|---|---|---|
| Encryption | GPG | DPAPI (Windows Credential Store) plus AES-256-GCM with a machine-bound, keyfile or TPM key |
| Sync | git | None (local only) |
| Multiline entries | Unlimited size | 2523 bytes max |
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
