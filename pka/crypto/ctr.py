"""CTR mode over a 16-byte block cipher."""

from pka.crypto.util import BLOCK_SIZE

def inc_counter_be(counter):
    # big-endian increment, matching Crypto++
    for i in range(BLOCK_SIZE - 1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break

class CTR:
    def __init__(self, encrypt_block, initial_counter):
        if len(initial_counter) != BLOCK_SIZE:
            raise ValueError(f"initial counter must be {BLOCK_SIZE} bytes")
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
