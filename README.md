# pka-rename

Rename the user profile embedded inside a Cisco Packet Tracer `.pka` / `.pkt` activity file.

```
$ pka-rename "assignment.pka" "Kieth Cozart"
reading assignment.pka ...
  decrypted XML: 8,262,162 bytes
  3 profile block(s) found: 'Guest'
  -> renaming to 'Kieth Cozart'
re-encrypting ...
  verified: re-decrypts cleanly with valid EAX tag
  backup written: assignment.pka.bak
done: assignment.pka (662,132 bytes)
```

## Requirements

- Python 3.9 - 3.11 (tested on 3.11): the `twofish` dependency still imports
  the `imp` module, removed in Python 3.12
- [pipx](https://pipx.pypa.io/) for the install below (on macOS: `brew install pipx`)
- Cisco Packet Tracer `.pka` / `.pkt` activity files - the file format is
  unchanged from PT 7.x through 9.x (tested against 9.0.1)

## Install

Clone the repo, then install with pipx (isolated venv, command available
from anywhere):

```sh
git clone <repo-url>
cd pka-rename
pipx install --python /opt/homebrew/bin/python3.11 .
```

If pipx is new to the machine: `brew install pipx`, then `pipx ensurepath`
and re-login so `~/.local/bin` is on PATH.

Then, from anywhere:

```sh
pka-rename <file.pka> "New Name"
```

Re-run the `pipx install` command after pulling source changes.
Uninstall with `pipx uninstall pka-rename`.

## Usage

```
usage: pka-rename [-h] [-o OUTPUT] [--no-backup] pka_file new_name

positional arguments:
  pka_file    the .pka or .pkt file to patch
  new_name    new profile name (replaces the current one)

options:
  -h, --help  show this help message and exit
  -o OUTPUT   write result to this path instead of editing in place
  --no-backup do not keep a .bak copy when editing in place
```

Defaults are safe: the file is edited in place only after a full round-trip verification (the re-encrypted output is decrypted again and must match the patched XML exactly, including the EAX authentication tag). A `.bak` copy of the original is kept unless `--no-backup` is given, and the write itself is atomic (`.tmp` + rename).

## How it works

Packet Tracer does not store plain XML on disk. A `.pka` file is:

```
.pka bytes = Stage1-obfuscate( Twofish-EAX( Stage2-obfuscate( qCompress(xml) ) ) )
```

| stage        | what it is |
|--------------|------------|
| qCompress    | Qt's zlib wrapper: 4-byte big-endian uncompressed size + zlib data |
| Stage 2      | XOR every byte with `(L - i) & 0xFF` — self-inverse |
| EAX          | Twofish-128, key `0x89 * 16`, nonce `0x10 * 16`, 16-byte tag appended last |
| Stage 1      | byte-reverse the buffer, XOR with `(L - i*L) & 0xFF` — scramble |

The script reverses the pipeline, replaces every `<USER_PROFILE><NAME>...</NAME>` occurrence in the XML (activities embed several copies of the workspace - initial network, answer network, activity - each carrying its own profile), then re-applies it.

## Credits

Format knowledge from [mircodz/pka2xml](https://github.com/mircodz/pka2xml) and [strykey/pka-decipher](https://github.com/strykey/pka-decipher).
