"""Minimal AppleDouble v2 writer for `._` sidecar files."""

import struct

APPLEDOUBLE_MAGIC = 0x00051607
APPLEDOUBLE_VERSION = 2
ENTRY_RESOURCE_FORK = 2
ENTRY_FINDER_INFO = 9


def appledouble_bytes(resource_fork, finder_info):
    """Return AppleDouble bytes for a `._` file, or None if there is
    nothing worth storing (no resource fork and no Finder info)."""
    entries = []
    if resource_fork:
        entries.append((ENTRY_RESOURCE_FORK, resource_fork))
    if finder_info:
        info = finder_info
        if len(info) < 32:
            info = info + b"\0" * (32 - len(info))
        elif len(info) > 32:
            info = info[:32]
        entries.append((ENTRY_FINDER_INFO, info))
    if not entries:
        return None

    header_size = 26 + 12 * len(entries)
    offset = header_size
    descriptors = []
    for entry_id, payload in entries:
        descriptors.append((entry_id, offset, len(payload)))
        offset += len(payload)

    out = [struct.pack(">II", APPLEDOUBLE_MAGIC, APPLEDOUBLE_VERSION), b"\0" * 16,
           struct.pack(">H", len(entries))]
    for entry_id, off, length in descriptors:
        out.append(struct.pack(">III", entry_id, off, length))
    for _, payload in entries:
        out.append(payload)
    return b"".join(out)
