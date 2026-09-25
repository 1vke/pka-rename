# pka-rename

Rename the user profile embedded inside a Cisco Packet Tracer `.pka` / `.pkt` activity file.

```
$ ./pka_rename.py "6.2.4 Packet Tracer - Configure EtherChannel.pka" "Lucas Lowe"
reading 6.2.4 Packet Tracer - Configure EtherChannel.pka ...
  decrypted XML: 8,262,162 bytes
  3 profile block(s) found: 'Guest'
  -> renaming to 'Lucas Lowe'
re-encrypting ...
  verified: re-decrypts cleanly with valid EAX tag
  backup written: 6.2.4 Packet Tracer - Configure EtherChannel.pka.bak
done: 6.2.4 Packet Tracer - Configure EtherChannel.pka (662,132 bytes)
```

## Install

`pka-rename` is packaged with a `pyproject.toml` console-script entry point,
so once installed the `pka-rename` command works from any directory.

### As a CLI app (pipx, recommended)

The [`twofish`](https://pypi.org/project/twofish/) dependency still imports
the removed `imp` module, so the app must run on **Python <= 3.11** - pass
it explicitly to pipx:

```sh
brew install pipx            # if not already installed
pipx ensurepath              # puts ~/.local/bin on PATH (re-login after)
pipx install --python /opt/homebrew/bin/python3.11 /path/to/pka-rename
```

Then, from anywhere:

```sh
pka-rename <file.pka> "New Name"
```

Uninstall with `pipx uninstall pka-rename`.

### Development install

```sh
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .          # adds .venv/bin/pka-rename
```

Or run straight from the source tree without installing:

```sh
.venv/bin/python pka_rename.py <file.pka> "New Name"
```

## Layout

```
pka_rename.py       executable entry point (thin wrapper -> pka.cli)
requirements.txt    twofish
pka/
├── cli.py          argument parsing, backup/verify/atomic-write logic
├── constants.py    Packet Tracer magic values: key byte 0x89, nonce byte 0x10
├── ptfile.py       file pipeline: XOR stages, qCompress, EAX glue
├── profile.py      <USER_PROFILE><NAME> extraction and renaming
└── crypto/
    ├── util.py     128-bit block size + shared byte helpers
    ├── cmac.py     CMAC (NIST SP 800-38B)
    ├── ctr.py      CTR counter mode
    └── eax.py      EAX authenticated encryption (OMAC0..2 + CTR)
```

The Twofish cipher comes from the `twofish` library; the CMAC / CTR / EAX
modes live in `pka/crypto/` because no mainstream crypto library ships EAX
over Twofish.

## Usage

```
usage: pka_rename.py [-h] [-o OUTPUT] [--no-backup] pka_file new_name

positional arguments:
  pka_file    the .pka or .pkt file to patch
  new_name    new profile name (replaces the current one)

options:
  -h, --help  show this help message and exit
  -o OUTPUT   write result to this path instead of editing in place
  --no-backup do not keep a .bak copy when editing in place
```

Defaults are safe: the file is edited in place only after a full round-trip
verification (the re-encrypted output is decrypted again and must match the
patched XML exactly, including the EAX authentication tag). A `.bak` copy of
the original is kept unless `--no-backup` is given, and the write itself is
atomic (`.tmp` + rename).

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

The script reverses the pipeline, replaces every
`<USER_PROFILE><NAME>...</NAME>` occurrence in the XML (activities embed
several copies of the workspace - initial network, answer network, activity -
each carrying its own profile), then re-applies it.

## Credits & disclaimer

Format knowledge comes from the reverse-engineering work in
[mircodz/pka2xml](https://github.com/mircodz/pka2xml) and
[strykey/pka-decipher](https://github.com/strykey/pka-decipher). The Twofish
constants (key/nonce) and pipeline description originate from those projects.

For educational use on your own files only ;).
