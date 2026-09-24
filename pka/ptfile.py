"""Packet Tracer file pipeline.

A .pka/.pkt file on disk is built (innermost first) as:

    1. qCompress(xml)      Qt's zlib wrapper: 4-byte big-endian uncompressed
                           size followed by a raw zlib stream
    2. stage 2 obfuscation out[i] = in[i] ^ ((L - i) & 0xFF)      (self-inverse)
    3. EAX encryption      Twofish-128, key PT_KEY, nonce PT_NONCE,
                           16-byte authentication tag appended last
    4. stage 1 obfuscation out[i] = in[L-1-i] ^ ((L - i*L) & 0xFF)  (scramble)

decrypt_pka() and encrypt_pka() reverse / apply exactly that pipeline.
"""

import struct
import zlib

from twofish import Twofish

from pka.constants import PT_KEY, PT_NONCE
from pka.crypto import EAX

# Number of leading bytes in a qCompress blob holding the uncompressed size
# (4-byte unsigned big-endian integer).
QT_HEADER_SIZE = 4

# Byte length of the EAX authentication tag carried at the end of the file.
TAG_SIZE = 16


# ---------------------------------------------------------------------------
# Stage 1: outermost scramble. Reverses byte order and XORs each byte with
# a mask derived from its position and the total length. Not encryption -
# just enough to stop casual inspection. The encrypt/deobfuscate pair below
# are exact inverses of each other.
# ---------------------------------------------------------------------------

def obf_stage1(data):
    L = len(data)
    out = bytearray(L)
    for i in range(L):
        out[L - 1 - i] = data[i] ^ ((L - i * L) & 0xFF)
    return bytes(out)


def deobf_stage1(data):
    L = len(data)
    return bytes(data[L - 1 - i] ^ ((L - i * L) & 0xFF) for i in range(L))


# ---------------------------------------------------------------------------
# Stage 2: inner XOR mask. XOR with a deterministic mask is its own inverse,
# so a single function serves both directions.
# ---------------------------------------------------------------------------

def obf_stage2(data):
    L = len(data)
    return bytes(b ^ ((L - i) & 0xFF) for i, b in enumerate(data))


deobf_stage2 = obf_stage2


# ---------------------------------------------------------------------------
# Qt qCompress / qUncompress
# ---------------------------------------------------------------------------

def qcompress(data):
    """Qt-compatible compression: size header + zlib stream."""
    return struct.pack(">I", len(data)) + zlib.compress(data)


def qdecompress(blob):
    size = struct.unpack(">I", blob[:QT_HEADER_SIZE])[0]
    return zlib.decompress(blob[QT_HEADER_SIZE:])[:size]


# ---------------------------------------------------------------------------
# Pipeline entry points
# ---------------------------------------------------------------------------

def make_eax():
    """EAX instance wired to the `twofish` library's block cipher."""
    return EAX(Twofish(PT_KEY).encrypt)


def decrypt_pka(raw):
    """Raw .pka/.pkt bytes -> decrypted XML bytes.

    Raises pka.crypto.AuthenticationError if the embedded tag does not
    match (truncated or non-Packet Tracer input).
    """
    stage1 = deobf_stage1(raw)
    body, tag = stage1[:-TAG_SIZE], stage1[-TAG_SIZE:]
    plaintext = make_eax().decrypt(nonce=PT_NONCE, ciphertext=body, tag=tag)
    return qdecompress(deobf_stage2(plaintext))


def encrypt_pka(xml):
    """XML bytes -> encrypted .pka/.pkt bytes."""
    ciphertext, tag = make_eax().encrypt(nonce=PT_NONCE,
                                         plaintext=obf_stage2(qcompress(xml)))
    return obf_stage1(ciphertext + tag)
