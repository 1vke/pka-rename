"""Command line interface for pka-rename."""

import argparse
import os
import shutil
import sys
import zlib

try:
    from pka.crypto import AuthenticationError
    from pka.ptfile import decrypt_pka, encrypt_pka
    from pka.profile import rename_profile
except ImportError as e:
    print(f"error: missing dependency ({e.name}) - set up the project venv:\n"
          "  python3.11 -m venv .venv\n"
          "  .venv/bin/pip install -r requirements.txt",
          file=sys.stderr)
    sys.exit(1)

# Process exit codes
EXIT_OK = 0
EXIT_INPUT_ERROR = 1    # input file missing or unreadable
EXIT_DECRYPT_ERROR = 2  # not a Packet Tracer file / unsupported format
EXIT_PATCH_ERROR = 3    # profile edit could not be applied
EXIT_VERIFY_ERROR = 4   # re-encryption failed the round-trip check

class CliError(Exception):
    """Fatal, user-facing error; carries the exit code main() should return."""

    def __init__(self, message, exit_code):
        super().__init__(message)
        self.exit_code = exit_code

def build_parser():
    ap = argparse.ArgumentParser(
        description="Rename the user profile embedded in a Cisco Packet Tracer "
                    ".pka/.pkt activity file (decrypt -> patch -> re-encrypt).")
    ap.add_argument("pka_file", help="the .pka or .pkt file to patch")
    ap.add_argument("new_name", help="new profile name (replaces the current one)")
    ap.add_argument("-o", "--output",
                    help="write result to this path instead of editing in place")
    ap.add_argument("--no-backup", action="store_true",
                    help="do not keep a .bak copy when editing in place")
    return ap

def read_source(path):
    """Validate and read the .pka/.pkt file."""
    if not os.path.isfile(path):
        raise CliError(f"file not found: {path}", EXIT_INPUT_ERROR)
    print(f"reading {path} ...")
    with open(path, "rb") as f:
        return f.read()

def decrypt_source(raw):
    """Decrypt the container into its XML payload."""
    try:
        xml = decrypt_pka(raw)
    except AuthenticationError as e:
        raise CliError(f"{e} (not a valid/complete Packet Tracer file, "
                       f"or unsupported format)", EXIT_DECRYPT_ERROR)
    except zlib.error:
        raise CliError("decompression failed - not a Packet Tracer file?",
                       EXIT_DECRYPT_ERROR)
    print(f"  decrypted XML: {len(xml):,} bytes")
    return xml

def apply_profile_edits(xml, new_name):
    """Apply the requested profile edits to the decrypted XML.

    Extension point: future edits (profile email, info fields, ...) slot in
    here as additional steps against the same decrypted XML, so the
    decrypt/encrypt/verify pipeline around them stays untouched.
    """
    try:
        xml_new, old_names = rename_profile(xml, new_name)
    except ValueError as e:
        raise CliError(str(e), EXIT_PATCH_ERROR)

    uniq_old = sorted(set(old_names))
    print(f"  {len(old_names)} profile block(s) found: "
          f"{', '.join(repr(n) for n in uniq_old)}")
    print(f"  -> renaming to {new_name!r}")
    return xml_new

def encrypt_and_verify(xml):
    """Re-encrypt the XML and prove it round-trips before writing anything."""
    print("re-encrypting ...")
    out = encrypt_pka(xml)
    if decrypt_pka(out) != xml:
        raise CliError("round-trip verification failed, file not modified",
                       EXIT_VERIFY_ERROR)
    print("  verified: re-decrypts cleanly with valid EAX tag")
    return out

def write_output(src, out, output=None, no_backup=False):
    """Atomically write the result, backing up the original when editing in place."""
    dest = output or src
    if output is None and not no_backup:
        bak = src + ".bak"
        if not os.path.exists(bak):
            shutil.copy2(src, bak)
            print(f"  backup written: {bak}")

    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, dest)
    print(f"done: {dest} ({len(out):,} bytes)")

def run(args):
    """Map parsed CLI arguments onto the patch pipeline and execute it."""
    raw = read_source(args.pka_file)
    xml = decrypt_source(raw)
    xml_new = apply_profile_edits(xml, args.new_name)
    out = encrypt_and_verify(xml_new)
    write_output(args.pka_file, out, output=args.output, no_backup=args.no_backup)
    return EXIT_OK

def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code
