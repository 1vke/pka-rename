"""<USER_PROFILE> extraction and field editing in decrypted Packet Tracer XML."""

import re
from xml.sax.saxutils import escape

# XML keys for relevant fields of a <USER_PROFILE> block.
FIELD_NAME = "NAME"
FIELD_EMAIL = "EMAIL"
FIELD_INFO = "ADDITIONAL_INFO"

PROFILE_BLOCK_RE = re.compile(rb'<USER_PROFILE>.*?</USER_PROFILE>', re.S)

def _field_re(field):
    """Regex for <FIELD>value</FIELD> inside a <USER_PROFILE> block."""
    tag = field.encode("utf-8")
    return re.compile(rb'(<' + tag + rb'>)([^<]*)(</' + tag + rb'>)')

def _find_field_values(xml, field):
    """Current values of a profile field, one per block that has one."""
    values = []
    for block in PROFILE_BLOCK_RE.finditer(xml):
        values.extend(m[1].decode("utf-8", "replace")
                      for m in _field_re(field).findall(block.group(0)))
    return values

def _edit_field(xml, field, new_value):
    """Replace every <USER_PROFILE><FIELD> value. Returns (patched_xml, old_values)."""
    field_re = _field_re(field)
    replacement = rb'\1' + escape(new_value).encode("utf-8") + rb'\3'
    old_values = []

    def patch(block_match):
        block = block_match.group(0)
        old_values.extend(m[1].decode("utf-8", "replace")
                          for m in field_re.findall(block))
        return field_re.sub(replacement, block)

    xml_new = PROFILE_BLOCK_RE.sub(patch, xml)
    if not old_values:
        raise ValueError(f"no <USER_PROFILE><{field}> block found in this file")
    return xml_new, old_values

def find_profile_names(xml):
    return _find_field_values(xml, FIELD_NAME)

def find_profile_emails(xml):
    return _find_field_values(xml, FIELD_EMAIL)

def find_profile_infos(xml):
    return _find_field_values(xml, FIELD_INFO)

def edit_profile_name(xml, new_name):
    return _edit_field(xml, FIELD_NAME, new_name)

def edit_profile_email(xml, new_email):
    return _edit_field(xml, FIELD_EMAIL, new_email)

def edit_profile_info(xml, new_info):
    return _edit_field(xml, FIELD_INFO, new_info)
