"""Magic values hardcoded in Packet Tracer (.pka/.pkt, versions 7.x-9.x)."""

KEY_SIZE = 16
NONCE_SIZE = 16

# every byte of the Twofish key / EAX nonce respectively
KEY_BYTE = 0x89
NONCE_BYTE = 0x10

PT_KEY = bytes([KEY_BYTE]) * KEY_SIZE
PT_NONCE = bytes([NONCE_BYTE]) * NONCE_SIZE
