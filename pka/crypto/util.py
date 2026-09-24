"""Helpers shared by the cipher mode implementations.

Every mode in this package assumes a 128-bit block cipher (Twofish, like
AES, operates exclusively on 16-byte blocks).
"""

# Twofish block size in bytes (fixed by the algorithm, like AES).
BLOCK_SIZE = 16


def xor_bytes(a, b):
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def left_shift_one(data):
    """Left-shift a byte string by one bit (used for CMAC subkey derivation)."""
    out = bytearray(len(data))
    carry = 0
    for i in reversed(range(len(data))):
        out[i] = ((data[i] << 1) & 0xFF) | carry
        carry = (data[i] & 0x80) >> 7
    return bytes(out)
