"""uuencode attachments (.uu, .uue), including Apple's MU multi-fork
layout.

A uuencode stream is one or more ``begin <mode> <name>`` ... ``end``
segments. The zero byte may be spelled as a space or a backquote. UUTool
writes the data fork first, then the resource fork (``name.rsrc``) and
then the Finder info (``name.finfo``) in the same stream; the resource
fork and Finder info are merged onto the entry for ``name`` instead of
being emitted as separate files.
"""

import re
import struct

from .._core import Archive, Entry
from ..errors import CorruptError

_BEGIN = re.compile(rb"(?m)^begin[ \t]+([0-7]+)[ \t]+(\S.*?)[ \t]*$")


def _decode_segment(lines, name):
    out = bytearray()
    for line in lines:
        if not line.strip():
            continue
        first = line[0]
        if first == ord("`"):
            count = 0
        elif first == ord(" "):
            count = 0
        else:
            count = first - 32
        if count < 0 or count > 63:
            raise CorruptError("uuencode: bad line length byte in %r" % name)
        body = line[1:].rstrip(b"\r\n")
        while len(body) < ((count + 2) // 3) * 4:
            body += b" "
        needed = ((count + 2) // 3) * 4
        body = body[:needed]
        chunk = bytearray()
        for i in range(0, len(body), 4):
            group = body[i:i + 4]
            values = []
            for ch in group:
                if ch == ord("`") or ch == ord(" "):
                    values.append(0)
                elif 32 <= ch <= 96:
                    values.append((ch - 32) & 0x3F)
                else:
                    raise CorruptError("uuencode: character out of range in %r" % name)
            b = (values[0] << 18) | (values[1] << 12) | (values[2] << 6) | values[3]
            chunk.append((b >> 16) & 0xFF)
            chunk.append((b >> 8) & 0xFF)
            chunk.append(b & 0xFF)
        out += chunk[:count]
    return bytes(out)


def _parse(data):
    lines = data.split(b"\n")
    segments = []
    current_name = None
    current_mode = None
    current_lines = []
    for line in lines:
        match = _BEGIN.match(line.rstrip(b"\r\n"))
        if match:
            if current_name is not None:
                segments.append((current_mode, current_name, current_lines))
            current_mode = int(match.group(1), 8)
            current_name = match.group(2).decode("mac_roman", errors="replace")
            current_lines = []
            continue
        if line.strip() == b"end":
            if current_name is not None:
                segments.append((current_mode, current_name, current_lines))
            current_name = None
            continue
        if current_name is not None:
            current_lines.append(line)
    if current_name is not None:
        segments.append((current_mode, current_name, current_lines))
    if not segments:
        raise CorruptError("uuencode: no 'begin' segments found")

    entries = []
    finfo = {}
    for mode, name, seg_lines in segments:
        payload = _decode_segment(seg_lines, name)
        lower = name.lower()
        if lower.endswith(".rsrc"):
            key = name[:-5]
            entries_rsrc = (key, payload)
            finfo.setdefault(key, {})["rsrc"] = payload
            continue
        if lower.endswith(".finfo"):
            key = name[:-6]
            finfo.setdefault(key, {})["finfo"] = payload
            continue
        entry = Entry(name=name, _data=payload, data_size=len(payload))
        entries.append(entry)

    # Merge MU fork sections onto their base entries.
    for entry in entries:
        extra = finfo.get(entry.name)
        if not extra:
            continue
        rsrc = extra.get("rsrc")
        if rsrc:
            entry._rsrc = rsrc
            entry.resource_size = len(rsrc)
        raw_finfo = extra.get("finfo")
        if raw_finfo and len(raw_finfo) >= 16:
            finder = raw_finfo[:16]
            entry.type = finder[:4]
            entry.creator = finder[4:8]
            flags = struct.unpack_from(">H", finder, 8)[0]
            entry.finder_flags = flags
            entry.locked = bool(flags & 0x8000)
            entry.finder_info = finder + b"\0" * 16

    # .finfo/.rsrc sections with no base entry become their own entries
    # so no data is silently dropped.
    known = {entry.name for entry in entries}
    for key, extra in finfo.items():
        if key not in known:
            rsrc = extra.get("rsrc", b"")
            entry = Entry(name=key, _data=b"", data_size=0,
                          _rsrc=rsrc, resource_size=len(rsrc))
            entries.append(entry)

    archive = Archive()
    archive.format = "uuencode"
    archive.entries = entries
    return archive


def probe(data):
    if _BEGIN.search(data[:512]):
        return 80
    return 0


def open_data(data, password=None, filename=None):
    # uuencode has no encryption; a supplied password is simply unused.
    return _parse(data)
