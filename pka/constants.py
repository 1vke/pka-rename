"""Magic values of the Packet Tracer .pka/.pkt file format.

Recovered by reverse engineering the Packet Tracer binary; see
mircodz/pka2xml and strykey/pka-decipher for the original work.
Packet Tracer hardcodes these values - they are the same across
versions 7.x through 9.x.
"""

# Twofish operates on 16-byte blocks; key and nonce are each one block.
BLOCK_SIZE = 16
KEY_SIZE = BLOCK_SIZE
NONCE_SIZE = BLOCK_SIZE
TAG_SIZE = BLOCK_SIZE

# Every byte of the "Packet Tracer Saves" Twofish-128 key is 0x89.
KEY_BYTE = 0x89
# Every byte of the fixed EAX nonce is 0x10.
NONCE_BYTE = 0x10

# The hardcoded Twofish key used for .pka/.pkt files.
PT_KEY = bytes([KEY_BYTE]) * KEY_SIZE

# The fixed EAX nonce used for .pka/.pkt files. (Nets/log files use
# different constants: key 0xBA * 16, nonce 0xBE * 16 - not handled here.)
PT_NONCE = bytes([NONCE_BYTE]) * NONCE_SIZE
