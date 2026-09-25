"""Packet Tracer .pka/.pkt pipeline: stage1(EAX(stage2(qcompress(xml))))."""

import struct
import zlib

from twofish import Twofish

from pka.constants import PT_KEY, PT_NONCE
from pka.crypto import EAX

QT_HEADER_SIZE = 4  # qCompress header: 4-byte big-endian uncompressed size
TAG_SIZE = 16

def obf_stage1(data):
    L = len(data)
    out = bytearray(L)
    for i in range(L):
        out[L - 1 - i] = data[i] ^ ((L - i * L) & 0xFF)
    return bytes(out)

def deobf_stage1(data):
    L = len(data)
    return bytes(data[L - 1 - i] ^ ((L - i * L) & 0xFF) for i in range(L))

def obf_stage2(data):
    L = len(data)
    return bytes(b ^ ((L - i) & 0xFF) for i, b in enumerate(data))

deobf_stage2 = obf_stage2  # XOR mask is self-inverse

def qcompress(data):
    return struct.pack(">I", len(data)) + zlib.compress(data)

def qdecompress(blob):
    size = struct.unpack(">I", blob[:QT_HEADER_SIZE])[0]
    return zlib.decompress(blob[QT_HEADER_SIZE:])[:size]

def make_eax():
    return EAX(Twofish(PT_KEY).encrypt)

def decrypt_pka(raw):
    """Raw .pka/.pkt bytes -> XML bytes (raises on tag mismatch)."""
    stage1 = deobf_stage1(raw)
    body, tag = stage1[:-TAG_SIZE], stage1[-TAG_SIZE:]
    plaintext = make_eax().decrypt(nonce=PT_NONCE, ciphertext=body, tag=tag)
    return qdecompress(deobf_stage2(plaintext))

def encrypt_pka(xml):
    """XML bytes -> encrypted .pka/.pkt bytes."""
    ciphertext, tag = make_eax().encrypt(nonce=PT_NONCE,
                                         plaintext=obf_stage2(qcompress(xml)))
    return obf_stage1(ciphertext + tag)
