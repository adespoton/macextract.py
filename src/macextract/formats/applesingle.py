"""AppleSingle and AppleDouble (RFC 1740, Apple Developer's Note 1990).

Magic numbers 0x00051600 (AppleSingle, one stream: forks + metadata)
and 0x00051607 (AppleDouble, metadata header only; the data fork lives
in a sibling file). Both are big-endian with a 16-byte zero filler, a
16-bit entry count and 12-byte entry descriptors (id, offset, length).
Predefined entry ids used here: 1 data fork, 2 resource fork, 3 real
name, 8 file dates (seconds since 2000-01-01 GMT), 9 Finder info,
10 Mac file info (ioFlAttrib, locked bit 0x01).

When a ``._foo`` AppleDouble file is opened through a filesystem path
whose sibling ``foo`` exists, the data fork is read from the sibling.
"""

import struct

from .._core import MAC_EPOCH_OFFSET, Archive, Entry
from ..errors import CorruptError

APPLESINGLE_MAGIC = 0x00051600
APPLEDOUBLE_MAGIC = 0x00051607
VERSION_40 = 0x00010000  # seen in the wild
VERSION_2 = 0x00020000
AS_EPOCH_TO_MAC_EPOCH = 3029529600  # seconds 1904-01-01 .. 2000-01-01

ENTRY_DATA = 1
ENTRY_RESOURCE = 2
ENTRY_REALNAME = 3
ENTRY_FILEDATES = 8
ENTRY_FINDERINFO = 9
ENTRY_MACINFO = 10

HEADER_SIZE = 26
DESCRIPTOR_SIZE = 12


def _parse(data, kind, filename_hint=None):
    if len(data) < HEADER_SIZE:
        raise CorruptError("AppleSingle/Double: file too small for a header")
    magic, version = struct.unpack_from(">II", data, 0)
    want_magic = APPLESINGLE_MAGIC if kind == "single" else APPLEDOUBLE_MAGIC
    if magic != want_magic:
        raise CorruptError("AppleSingle/Double: wrong magic 0x%08x" % magic)
    if version not in (VERSION_2, VERSION_40):
        raise CorruptError("AppleSingle/Double: unsupported version 0x%08x" % version)
    count = struct.unpack_from(">H", data, 24)[0]
    table_end = HEADER_SIZE + DESCRIPTOR_SIZE * count
    if len(data) < table_end:
        raise CorruptError("AppleSingle/Double: truncated entry table")

    entries = {}
    for index in range(count):
        base = HEADER_SIZE + DESCRIPTOR_SIZE * index
        entry_id, offset, length = struct.unpack_from(">III", data, base)
        if entry_id == 0:
            raise CorruptError("AppleSingle/Double: entry id 0 is invalid")
        if offset + length > len(data):
            raise CorruptError("AppleSingle/Double: entry %d points past end of file" % entry_id)
        if entry_id not in entries:
            entries[entry_id] = data[offset:offset + length]

    name = None
    if ENTRY_REALNAME in entries:
        try:
            name = entries[ENTRY_REALNAME].decode("mac_roman")
        except UnicodeDecodeError:
            name = entries[ENTRY_REALNAME].decode("mac_roman", errors="replace")
    if not name:
        if filename_hint:
            name = filename_hint
        elif kind == "double":
            name = "unnamed"
        else:
            name = "unnamed"

    created = modified = 0
    if ENTRY_FILEDATES in entries and len(entries[ENTRY_FILEDATES]) >= 8:
        raw_create, raw_modify = struct.unpack_from(">ii", entries[ENTRY_FILEDATES], 0)
        created = raw_create + AS_EPOCH_TO_MAC_EPOCH
        modified = raw_modify + AS_EPOCH_TO_MAC_EPOCH

    finder_info = entries.get(ENTRY_FINDERINFO)
    if finder_info is not None and len(finder_info) not in (16, 32):
        raise CorruptError("AppleSingle/Double: Finder info of %d bytes" % len(finder_info))
    if finder_info is not None and len(finder_info) == 16:
        finder_info = finder_info + b"\0" * 16

    flags = 0
    file_type = b"????"
    creator = b"????"
    if finder_info:
        file_type, creator = finder_info[:4], finder_info[4:8]
        flags = struct.unpack_from(">H", finder_info, 8)[0]

    # Locked/protected come from the Mac file info attributes, not from
    # the Finder flags (bit 0x8000 of those is the alias bit).
    locked = False
    protected = False
    if ENTRY_MACINFO in entries and len(entries[ENTRY_MACINFO]) >= 4:
        attrib = entries[ENTRY_MACINFO][3]
        locked = bool(attrib & 0x01)
        protected = bool(attrib & 0x02)

    fork_data = entries.get(ENTRY_DATA, b"")
    fork_rsrc = entries.get(ENTRY_RESOURCE, b"")

    entry = Entry(
        name=name,
        type=file_type,
        creator=creator,
        finder_flags=flags,
        locked=locked,
        created=created,
        modified=modified,
        finder_info=finder_info,
        data_size=len(fork_data),
        resource_size=len(fork_rsrc),
        _data=fork_data,
        _rsrc=fork_rsrc,
    )
    entry.protected = protected
    archive = Archive()
    archive.format = "AppleSingle" if kind == "single" else "AppleDouble"
    archive.entries = [entry]
    return archive


def probe(data):
    if len(data) < 4:
        return 0
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (APPLESINGLE_MAGIC, APPLEDOUBLE_MAGIC):
        return 95
    return 0


def open_data(data, password=None, filename=None):
    # AppleSingle/Double has no encryption; a supplied password is unused.
    magic = struct.unpack_from(">I", data, 0)[0] if len(data) >= 4 else None
    if magic == APPLESINGLE_MAGIC:
        kind = "single"
    elif magic == APPLEDOUBLE_MAGIC:
        kind = "double"
    else:
        raise CorruptError("AppleSingle/Double: not an AppleSingle/Double file")
    hint = filename
    if hint:
        base = hint.replace("\\", "/").rsplit("/", 1)[-1]
        if base.startswith("._"):
            base = base[2:]
        hint = base or None
    return _parse(data, kind, filename_hint=hint)
