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


def main(argv=None):
    args = build_parser().parse_args(argv)
    src = args.pka_file

    if not os.path.isfile(src):
        print(f"error: file not found: {src}", file=sys.stderr)
        return 1

    print(f"reading {src} ...")
    raw = open(src, "rb").read()

    try:
        xml = decrypt_pka(raw)
    except AuthenticationError as e:
        print(f"error: {e} (not a valid/complete Packet Tracer file, "
              f"or unsupported format)", file=sys.stderr)
        return 2
    except zlib.error:
        print("error: decompression failed - not a Packet Tracer file?",
              file=sys.stderr)
        return 2
    print(f"  decrypted XML: {len(xml):,} bytes")

    try:
        xml_new, old_names = rename_profile(xml, args.new_name)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    uniq_old = sorted(set(old_names))
    print(f"  {len(old_names)} profile block(s) found: "
          f"{', '.join(repr(n) for n in uniq_old)}")
    print(f"  -> renaming to {args.new_name!r}")

    print("re-encrypting ...")
    out = encrypt_pka(xml_new)

    if decrypt_pka(out) != xml_new:
        print("error: round-trip verification failed, file not modified",
              file=sys.stderr)
        return 4
    print("  verified: re-decrypts cleanly with valid EAX tag")

    dest = args.output or src
    if args.output is None and not args.no_backup:
        bak = src + ".bak"
        if not os.path.exists(bak):
            shutil.copy2(src, bak)
            print(f"  backup written: {bak}")

    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, dest)
    print(f"done: {dest} ({len(out):,} bytes)")
    return 0
