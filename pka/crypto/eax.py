"""EAX authenticated encryption: tag = OMAC0(nonce) ^ OMAC1(aad) ^ OMAC2(ciphertext)."""

from pka.crypto.cmac import CMAC
from pka.crypto.ctr import CTR
from pka.crypto.util import BLOCK_SIZE, xor_bytes

# Domain-separation prefixes for the three OMAC computations.
OMAC_PREFIX_NONCE = 0x00  # doubles as the CTR starting counter
OMAC_PREFIX_AAD = 0x01
OMAC_PREFIX_DATA = 0x02

class AuthenticationError(ValueError):
    """EAX tag mismatch during decryption."""

def _omac_with_prefix(cmac, prefix, data):
    prefix_block = bytes([prefix]).rjust(BLOCK_SIZE, b"\x00")
    return cmac.digest(prefix_block + data)

class EAX:
    def __init__(self, encrypt_block):
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
