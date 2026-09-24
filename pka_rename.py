#!/usr/bin/env python3
"""
pka_rename.py - rename the user profile inside a Cisco Packet Tracer .pka/.pkt file.

Rewrites the <USER_PROFILE><NAME>...</NAME> entry embedded in the (encrypted)
XML payload of the activity file, then re-encrypts the file in place so
Packet Tracer opens it without complaint.

Usage:
    python3 pka_rename.py <file.pka> "New Name"
    python3 pka_rename.py <file.pka> "New Name" -o out.pka
    python3 pka_rename.py <file.pka> "New Name" --no-backup

Requires the `twofish` package (Python <= 3.11, see README):
    python3 -m pip install twofish

File format (reversed from Packet Tracer 7.x-9.x, see mircodz/pka2xml and
strykey/pka-decipher):

    .pka bytes = Stage1-obfuscate( Twofish-EAX( Stage2-obfuscate( qCompress(xml) ) ) )
    - Stage 1: byte-reverse + XOR with (L - i*L) & 0xFF        (scramble)
    - EAX    : Twofish-128, key = 0x89*16, nonce = 0x10*16, tag appended last
    - Stage 2: XOR with (L - i) & 0xFF                          (self-inverse)
    - qCompress: 4-byte big-endian uncompressed size + zlib data
"""

import argparse
import os
import re
import shutil
import struct
import sys
import zlib
from xml.sax.saxutils import escape

try:
    from twofish import Twofish
except ImportError:
    print("error: missing dependency - install with:  python3 -m pip install twofish\n"
          "(note: the twofish package needs Python <= 3.11)",
          file=sys.stderr)
    sys.exit(1)

# ============================================================================
# CMAC / CTR / EAX over any 128-bit block cipher
# (no library ships EAX for Twofish, so these modes are implemented here)
# ============================================================================

BLOCK_SIZE = 16

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def left_shift_one(bitstring):
    out = bytearray(len(bitstring))
    carry = 0
    for i in reversed(range(len(bitstring))):
        new = (bitstring[i] << 1) & 0xFF
        out[i] = new | carry
        carry = (bitstring[i] & 0x80) >> 7
    return bytes(out)

def generate_subkeys(encrypt_block):
    const_rb = 0x87
    L = encrypt_block(bytes(BLOCK_SIZE))
    K1 = left_shift_one(L)
    if L[0] & 0x80:
        K1 = xor_bytes(K1, b'\x00' * 15 + bytes([const_rb]))
    K2 = left_shift_one(K1)
    if K1[0] & 0x80:
        K2 = xor_bytes(K2, b'\x00' * 15 + bytes([const_rb]))
    return K1, K2

def cmac_pad(block):
    padded = block + b'\x80'
    return padded + b'\x00' * (BLOCK_SIZE - len(padded))

class CMAC:
    def __init__(self, encrypt_block):
        self.encrypt_block = encrypt_block
        self.K1, self.K2 = generate_subkeys(encrypt_block)

    def digest(self, data):
        if len(data) == 0:
            last = xor_bytes(cmac_pad(b''), self.K2)
            blocks = []
        else:
            blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
            if len(blocks[-1]) == BLOCK_SIZE:
                last = xor_bytes(blocks[-1], self.K1)
            else:
                last = xor_bytes(cmac_pad(blocks[-1]), self.K2)
            blocks = blocks[:-1]

        X = bytes(BLOCK_SIZE)
        for block in blocks:
            X = self.encrypt_block(xor_bytes(X, block))
        return self.encrypt_block(xor_bytes(X, last))

def inc_counter_be(counter):
    for i in range(BLOCK_SIZE - 1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break

class CTR:
    def __init__(self, encrypt_block, initial_counter):
        self.encrypt_block = encrypt_block
        self.counter = bytearray(initial_counter)

    def process(self, data):
        out = bytearray()
        offset = 0
        while offset < len(data):
            keystream = self.encrypt_block(bytes(self.counter))
            inc_counter_be(self.counter)
            block = data[offset:offset + BLOCK_SIZE]
            out.extend(b ^ k for b, k in zip(block, keystream))
            offset += BLOCK_SIZE
        return bytes(out)

def _omac_with_prefix(cmac, prefix, data):
    P = b'\x00' * (BLOCK_SIZE - 1) + bytes([prefix])
    return cmac.digest(P + data)

class EAX:
    def __init__(self, encrypt_block):
        self.encrypt_block = encrypt_block
        self.cmac = CMAC(encrypt_block)

    def encrypt(self, nonce, plaintext, aad=b''):
        n_tag = _omac_with_prefix(self.cmac, 0x00, nonce)
        h_tag = _omac_with_prefix(self.cmac, 0x01, aad)
        ctr = CTR(self.encrypt_block, n_tag)
        ciphertext = ctr.process(plaintext)
        c_tag = _omac_with_prefix(self.cmac, 0x02, ciphertext)
        tag = xor_bytes(xor_bytes(n_tag, h_tag), c_tag)
        return ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag, aad=b''):
        n_tag = _omac_with_prefix(self.cmac, 0x00, nonce)
        ctr = CTR(self.encrypt_block, n_tag)
        plaintext = ctr.process(ciphertext)
        h_tag = _omac_with_prefix(self.cmac, 0x01, aad)
        c_tag = _omac_with_prefix(self.cmac, 0x02, ciphertext)
        if xor_bytes(xor_bytes(n_tag, h_tag), c_tag) != tag:
            raise ValueError("EAX authentication failed (not a valid/complete "
                             "Packet Tracer file, or unsupported format)")
        return plaintext

# ============================================================================
# Packet Tracer file pipeline
# ============================================================================

PT_KEY   = bytes([137]) * 16   # "Packet Tracer Saves" Twofish-128 key
PT_NONCE = bytes([16])  * 16   # fixed EAX nonce

def obf_stage1(data):
    L = len(data)
    o = bytearray(L)
    for i in range(L):
        o[L-1-i] = data[i] ^ ((L - i*L) & 0xFF)
    return bytes(o)

def deobf_stage1(data):
    L = len(data)
    return bytes(data[L-1-i] ^ (L - i*L & 0xFF) for i in range(L))

def obf_stage2(data):
    L = len(data)
    return bytes(b ^ (L - i & 0xFF) for i, b in enumerate(data))

deobf_stage2 = obf_stage2  # XOR with deterministic mask: self-inverse

def qcompress(data):
    return struct.pack(">I", len(data)) + zlib.compress(data)

def qdecompress(blob):
    size = struct.unpack(">I", blob[:4])[0]
    return zlib.decompress(blob[4:])[:size]

def make_eax():
    """EAX instance over the `twofish` library's block cipher."""
    return EAX(Twofish(PT_KEY).encrypt)

def decrypt_pka(raw):
    """raw .pka/.pkt bytes -> decrypted XML bytes. Raises on auth failure."""
    stage1 = deobf_stage1(raw)
    plaintext = make_eax().decrypt(nonce=PT_NONCE,
                                   ciphertext=stage1[:-16],
                                   tag=stage1[-16:])
    return qdecompress(deobf_stage2(plaintext))

def encrypt_pka(xml):
    """XML bytes -> encrypted .pka/.pkt bytes."""
    ct, tag = make_eax().encrypt(nonce=PT_NONCE, plaintext=obf_stage2(qcompress(xml)))
    return obf_stage1(ct + tag)

# ============================================================================
# Profile rename
# ============================================================================

PROFILE_RE = re.compile(rb'(<USER_PROFILE>\s*<NAME>)([^<]*)(</NAME>)')

def rename_profile(xml, new_name):
    """Replace every <USER_PROFILE><NAME> in the XML. Returns (xml, old_names)."""
    new_name_b = escape(new_name).encode("utf-8")
    old_names = [m[1].decode("utf-8", "replace") for m in PROFILE_RE.findall(xml)]
    if not old_names:
        raise ValueError("no <USER_PROFILE><NAME> block found in this file")
    xml_new = PROFILE_RE.sub(rb'\1' + new_name_b + rb'\3', xml)
    return xml_new, old_names

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="pka_rename.py",
        description="Rename the user profile embedded in a Cisco Packet Tracer "
                    ".pka/.pkt activity file (decrypt -> patch -> re-encrypt).")
    ap.add_argument("pka_file", help="the .pka or .pkt file to patch")
    ap.add_argument("new_name", help="new profile name (replaces the current one)")
    ap.add_argument("-o", "--output",
                    help="write result to this path instead of editing in place")
    ap.add_argument("--no-backup", action="store_true",
                    help="do not keep a .bak copy when editing in place")
    args = ap.parse_args(argv)

    src = args.pka_file
    if not os.path.isfile(src):
        print(f"error: file not found: {src}", file=sys.stderr)
        return 1

    print(f"reading {src} ...")
    raw = open(src, "rb").read()

    try:
        xml = decrypt_pka(raw)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
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
    print(f"  {len(old_names)} profile block(s) found: {', '.join(repr(n) for n in uniq_old)}")
    print(f"  -> renaming to {args.new_name!r}")

    print("re-encrypting ...")
    out = encrypt_pka(xml_new)

    # verify before writing anything
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

if __name__ == "__main__":
    sys.exit(main())
