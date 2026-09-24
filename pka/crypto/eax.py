"""EAX authenticated encryption (Bellare, Rogaway, Wagner) built from
CMAC and CTR over a 16-byte block cipher.

Tag = OMAC_0(nonce) ^ OMAC_1(aad) ^ OMAC_2(ciphertext), where OMAC_n
means CMAC over a message prefixed with a single domain-separation byte.
The OMAC_0 output doubles as the CTR starting counter.
"""

from pka.crypto.cmac import CMAC
from pka.crypto.ctr import CTR
from pka.crypto.util import BLOCK_SIZE, xor_bytes

# OMAC domain-separation prefixes: the message fed to CMAC is 15 zero bytes
# followed by one of these, so the three MAC computations cannot collide.
OMAC_PREFIX_NONCE = 0x00  # over the nonce    -> CTR starting counter
OMAC_PREFIX_AAD = 0x01    # over the header   -> header tag
OMAC_PREFIX_DATA = 0x02   # over the payload  -> ciphertext tag

TAG_SIZE = BLOCK_SIZE


class AuthenticationError(ValueError):
    """Raised when an EAX tag does not match during decryption."""


def _omac_with_prefix(cmac, prefix, data):
    prefix_block = bytes([prefix]).rjust(BLOCK_SIZE, b"\x00")
    return cmac.digest(prefix_block + data)


class EAX:
    def __init__(self, encrypt_block):
        """`encrypt_block` must be a callable: 16 bytes in -> 16 bytes out."""
        self.encrypt_block = encrypt_block
        self.cmac = CMAC(encrypt_block)

    def encrypt(self, nonce, plaintext, aad=b""):
        n_tag = _omac_with_prefix(self.cmac, OMAC_PREFIX_NONCE, nonce)
        h_tag = _omac_with_prefix(self.cmac, OMAC_PREFIX_AAD, aad)
        ctr = CTR(self.encrypt_block, n_tag)
        ciphertext = ctr.process(plaintext)
        c_tag = _omac_with_prefix(self.cmac, OMAC_PREFIX_DATA, ciphertext)
        tag = xor_bytes(xor_bytes(n_tag, h_tag), c_tag)
        return ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag, aad=b""):
        n_tag = _omac_with_prefix(self.cmac, OMAC_PREFIX_NONCE, nonce)
        ctr = CTR(self.encrypt_block, n_tag)
        plaintext = ctr.process(ciphertext)
        h_tag = _omac_with_prefix(self.cmac, OMAC_PREFIX_AAD, aad)
        c_tag = _omac_with_prefix(self.cmac, OMAC_PREFIX_DATA, ciphertext)
        if xor_bytes(xor_bytes(n_tag, h_tag), c_tag) != tag:
            raise AuthenticationError("EAX authentication failed: tag mismatch")
        return plaintext
