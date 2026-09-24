"""User profile extraction and renaming inside decrypted Packet Tracer XML."""

import re
from xml.sax.saxutils import escape

# A packet tracer activity embeds several copies of the workspace document
# (initial network, answer network, activity), each carrying its own
# <USER_PROFILE> block. Only <NAME> elements inside those blocks are
# touched - <NAME> appears elsewhere in the XML (clusters, devices, ...)
# and must be left alone.
PROFILE_RE = re.compile(rb'(<USER_PROFILE>\s*<NAME>)([^<]*)(</NAME>)')


def find_profiles(xml):
    """Return the current profile names in the XML (one per profile block)."""
    return [m[1].decode("utf-8", "replace") for m in PROFILE_RE.findall(xml)]


def rename_profile(xml, new_name):
    """Replace every <USER_PROFILE><NAME> in the XML.

    Returns (patched_xml, old_names). Raises ValueError if the XML contains
    no profile block at all.
    """
    old_names = find_profiles(xml)
    if not old_names:
        raise ValueError("no <USER_PROFILE><NAME> block found in this file")
    # XML-escape the new name so &, < and > cannot corrupt the document.
    replacement = rb'\1' + escape(new_name).encode("utf-8") + rb'\3'
    return PROFILE_RE.sub(replacement, xml), old_names
