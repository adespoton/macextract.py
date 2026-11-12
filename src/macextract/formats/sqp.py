"""AppleLink package (.pkg) — SqueezePlay.

A package is two directories and then the members' bytes. Everything
is addressed absolutely.

  +0   u8     items in the SQP directory (<= 50; folders are skipped,
              so the count may be lower than the entry count)
  +1   u8     version: 0 or 1
  +2   u8[8]  bytes nothing reads
  +10         SQP directory: count x 86-byte records

Version 1 — the layout both real packages and Aladdin's own writer
produce — carries a second directory, and that is the one read:

  +86n+10  u32  items in the HFS directory, then eight zero bytes
  +86n+22       HFS directory: count x 90-byte records, each a u16
                LEVEL and a u16 that is non-zero for a FOLDER,
                followed by the same 86-byte record

then the members' bytes. The two counts need not agree; the header's
count locates the HFS directory.

Records carry both forks as (compressed length, absolute offset,
expanded length), plus a flag byte with one stored bit per fork:

  +4   resource fork, compressed    +16  resource fork, absolute offset
  +8   data fork, compressed        +12  data fork, absolute offset
  +20  16 bytes Finder info (FInfo for a file, DInfo for a folder;
       a folder's first eight bytes are its window rectangle)
  +36  Str31 name;  +68/+72 the created/modified dates (Mac epoch)
  +76  resource fork, expanded      +80  data fork, expanded
  +84  flags: bit 0x02 = data fork stored, bit 0x04 = resource fork
       stored

Forks are Unix compress(1) LZW — 13 bits, block mode (clear code
enabled) — except the stored ones. There is no checksum of any kind; a
fork is complete when its stream yields the declared expanded length.

Folders appear in the records as zero-length items; they contribute
path components for the items inside them and are not emitted as
entries of their own.
"""

import struct

from .._core import Archive, Entry
from .._lzw import lzw_decompress
from ..errors import CorruptError

SQP_RCL, SQP_DCL, SQP_DOFF, SQP_ROFF = 4, 8, 12, 16
SQP_FINDER, SQP_NAME, SQP_CTIME, SQP_MTIME = 20, 36, 68, 72
SQP_RLEN, SQP_DLEN, SQP_FLAGS = 76, 80, 84
SQP_F_STORED_DATA = 0x02
SQP_F_STORED_RSRC = 0x04
HEADER_SIZE = 10
RECORD_SIZE = 86
HFS_RECORD_SIZE = 90


def _mac_name(buf, offset):
    length = buf[offset]
    if length > 31:
        length = 31
    raw = buf[offset + 1: offset + 1 + length]
    try:
        return raw.decode("mac_roman")
    except UnicodeDecodeError:
        return raw.decode("mac_roman", errors="replace")


def _read_fork(data, off, clen, elen, stored, label):
    if elen == 0:
        return b""
    if off + clen > len(data):
        raise CorruptError("AppleLink: %s fork points past end of file" % label)
    if stored:
        if clen != elen:
            raise CorruptError("AppleLink: stored %s fork length mismatch" % label)
        return data[off:off + clen]
    return lzw_decompress(data, elen, maxbits=13, blockmode=True,
                          offset=off, limit=clen)


def _record_view(rec, pre):
    return rec[pre:] if pre else rec


def _parse(data):
    if len(data) < HEADER_SIZE:
        raise CorruptError("AppleLink: file too small for a header")
    sqp_count = data[0]
    version = data[1]
    if version > 1:
        raise CorruptError("AppleLink: unsupported version %d" % version)
    if version == 0:
        items = sqp_count
        base = HEADER_SIZE
        stride = RECORD_SIZE
        pre = 0
    else:
        base = HEADER_SIZE + RECORD_SIZE * sqp_count
        if base + 12 > len(data):
            raise CorruptError("AppleLink: truncated HFS directory header")
        items = struct.unpack_from(">I", data, base)[0]
        if items > 0xFFFF:
            raise CorruptError("AppleLink: implausible item count %d" % items)
        base += 12
        stride = HFS_RECORD_SIZE
        pre = 4
    if base > len(data) or items > (len(data) - base) // stride:
        raise CorruptError("AppleLink: truncated directory")

    entries = []
    path_stack = []
    for index in range(items):
        start = base + stride * index
        rec = data[start:start + stride]
        level = 1
        folder = False
        if pre:
            level = max(1, struct.unpack_from(">H", rec, 0)[0])
            folder = struct.unpack_from(">H", rec, 2)[0] != 0
        r = _record_view(rec, pre)

        name = _mac_name(r, SQP_NAME)
        while len(path_stack) >= level:
            path_stack.pop()
        flags16 = struct.unpack_from(">H", r, 28)[0]
        type_code = r[20:24]
        creator = r[24:28]
        finder_info = bytes(r[20:36]) + b"\0" * 16
        created, modified = struct.unpack_from(">II", r, SQP_CTIME)

        if folder:
            path_stack.append(name)
            continue

        full_name = "/".join(path_stack + [name])
        dclen = struct.unpack_from(">I", r, SQP_DCL)[0]
        rclen = struct.unpack_from(">I", r, SQP_RCL)[0]
        doff = struct.unpack_from(">I", r, SQP_DOFF)[0]
        roff = struct.unpack_from(">I", r, SQP_ROFF)[0]
        dlen = struct.unpack_from(">I", r, SQP_DLEN)[0]
        rlen = struct.unpack_from(">I", r, SQP_RLEN)[0]
        stored_data = bool(r[SQP_FLAGS] & SQP_F_STORED_DATA)
        stored_rsrc = bool(r[SQP_FLAGS] & SQP_F_STORED_RSRC)

        entry = Entry(
            name=full_name,
            type=type_code,
            creator=creator,
            finder_flags=flags16,
            locked=bool(flags16 & 0x8000),
            created=created,
            modified=modified,
            finder_info=finder_info,
            data_size=dlen,
            resource_size=rlen,
        )
        entry._data = _read_fork(data, doff, dclen, dlen, stored_data, "data")
        entry._rsrc = _read_fork(data, roff, rclen, rlen, stored_rsrc, "resource")
        entries.append(entry)

    archive = Archive()
    archive.format = "AppleLink package"
    archive.entries = entries
    return archive


def probe(data):
    if len(data) < HEADER_SIZE:
        return 0
    sqp_count, version = data[0], data[1]
    if version > 1 or sqp_count > 50:
        return 0
    if version == 0:
        if sqp_count == 0:
            # Only an exactly-sized header is an empty v0 package;
            # otherwise a zero file is not ours to claim.
            return 20 if len(data) == HEADER_SIZE else 0
        if HEADER_SIZE + RECORD_SIZE * sqp_count > len(data):
            return 0
        if data[HEADER_SIZE + SQP_NAME] == 0:
            return 0  # first record's name length must be set
        return 20
    base = HEADER_SIZE + RECORD_SIZE * sqp_count
    if base + 12 > len(data):
        return 0
    items = struct.unpack_from(">I", data, base)[0]
    if items == 0:
        return 45 if len(data) == base + 12 else 0
    if items > 0xFFFF or base + 12 + HFS_RECORD_SIZE * items > len(data):
        return 0
    # First HFS record's name length must be set.
    if data[base + 12 + 4 + SQP_NAME] == 0:
        return 0
    return 45


def open_data(data, password=None, filename=None):
    # AppleLink packages have no encryption; a supplied password is unused.
    return _parse(data)
