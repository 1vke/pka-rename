"""Shared helpers for the cipher modes (all assume a 16-byte block)."""

BLOCK_SIZE = 16

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def left_shift_one(data):
    out = bytearray(len(data))
    carry = 0
    for i in reversed(range(len(data))):
        out[i] = ((data[i] << 1) & 0xFF) | carry
        carry = (data[i] & 0x80) >> 7
    return bytes(out)
