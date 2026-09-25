"""<USER_PROFILE> extraction and renaming in decrypted Packet Tracer XML."""

import re
from xml.sax.saxutils import escape

# Activities embed several workspace copies (initial network, answer
# network, activity), each with its own <USER_PROFILE>. The match is
# scoped to those blocks because <NAME> appears elsewhere in the XML.
PROFILE_RE = re.compile(rb'(<USER_PROFILE>\s*<NAME>)([^<]*)(</NAME>)')


def find_profiles(xml):
    """Current profile names, one per embedded workspace copy."""
    return [m[1].decode("utf-8", "replace") for m in PROFILE_RE.findall(xml)]


def rename_profile(xml, new_name):
    """Replace every profile name. Returns (patched_xml, old_names)."""
    old_names = find_profiles(xml)
    if not old_names:
        raise ValueError("no <USER_PROFILE><NAME> block found in this file")
    replacement = rb'\1' + escape(new_name).encode("utf-8") + rb'\3'
    return PROFILE_RE.sub(replacement, xml), old_names
