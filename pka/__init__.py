"""pka - rename the user profile inside Cisco Packet Tracer .pka/.pkt files.

Public API:
    decrypt_pka(raw)            raw file bytes -> XML bytes
    encrypt_pka(xml)            XML bytes -> raw file bytes
    rename_profile(xml, name)   patch every <USER_PROFILE><NAME>
    find_profiles(xml)          list current profile names

PT_KEY / PT_NONCE in pka.constants hold the format's magic values.
"""

from pka.constants import PT_KEY, PT_NONCE
from pka.profile import find_profiles, rename_profile
from pka.ptfile import decrypt_pka, encrypt_pka

__all__ = [
    "PT_KEY",
    "PT_NONCE",
    "decrypt_pka",
    "encrypt_pka",
    "rename_profile",
    "find_profiles",
]
