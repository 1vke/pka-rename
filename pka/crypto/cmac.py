"""CMAC (cipher-based MAC, NIST SP 800-38B) over any 16-byte block cipher."""

from pka.crypto.util import BLOCK_SIZE, left_shift_one, xor_bytes

# Subkey constant: the irreducible polynomial x^128 + x^7 + x^2 + x + 1
# for the GF(2^128) field, encoded as the low byte of the XOR mask.
CONST_RB = 0x87

# Most-significant bit of a byte; decides whether a shifted subkey must be
# reduced modulo the irreducible polynomial above.
MSB_MASK = 0x80

# First padding byte that marks where a partial final block ends.
PAD_BYTE = 0x80


def generate_subkeys(encrypt_block):
    """Derive the CMAC subkeys K1/K2 from the cipher itself (encrypting a
    zero block, then doubling in GF(2^128) with conditional XOR of CONST_RB)."""
    L = encrypt_block(bytes(BLOCK_SIZE))

    K1 = left_shift_one(L)
    if L[0] & MSB_MASK:
        K1 = xor_bytes(K1, bytes([CONST_RB]).rjust(BLOCK_SIZE, b"\x00"))

    K2 = left_shift_one(K1)
    if K1[0] & MSB_MASK:
        K2 = xor_bytes(K2, bytes([CONST_RB]).rjust(BLOCK_SIZE, b"\x00"))

    return K1, K2


def pad(block):
    """Append the end-of-data marker and zero-fill to a full block."""
    padded = block + bytes([PAD_BYTE])
    return padded.ljust(BLOCK_SIZE, b"\x00")


class CMAC:
    def __init__(self, encrypt_block):
        self.encrypt_block = encrypt_block
        self.K1, self.K2 = generate_subkeys(encrypt_block)

    def digest(self, data):
        """Produce the 16-byte CMAC tag of `data`."""
        if len(data) == 0:
            blocks = []
            last = xor_bytes(pad(b""), self.K2)
        else:
            blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
            if len(blocks[-1]) == BLOCK_SIZE:
                # complete final block: XOR with K1
                last = xor_bytes(blocks[-1], self.K1)
            else:
                # partial final block: pad, then XOR with K2
                last = xor_bytes(pad(blocks[-1]), self.K2)
            blocks = blocks[:-1]

        X = bytes(BLOCK_SIZE)
        for block in blocks:
            X = self.encrypt_block(xor_bytes(X, block))
        return self.encrypt_block(xor_bytes(X, last))
