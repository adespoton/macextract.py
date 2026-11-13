"""MAR reader — Hampa Hug's archive (``.mar``, ``.mac``).

MAR is a cross between MacBinary and Unix tar: every Finder field is
kept, and an archive holds exactly one item — a single file, or a
folder tree.  This reader follows the layout published in the
archiveteam wiki (*MAR Utility*) as implemented by the format's author
and the C MacExtract project's measured behaviour:

- The archive is a sequence of 128-byte records.  The first four bytes
  are ``MAR\\x80``; bytes 4..7 name the record: ``'file'``, ``'fold'``
  (folder start) or ``'----'`` (folder end).
- Bytes 8..71 are a Pascal string: a length byte and up to 63 bytes of
  Mac-Roman name, zero padded.
- Bytes 72..75, 76..79, 80..83 are the data-fork, resource-fork and
  comment sizes in bytes; byte 84..87 are the file flags (bit 0
  locked, bit 1 protected, bit 4 a folder); 88..91 and 92..95 are the
  creation and modification dates (Mac 1904 epoch, seconds); 96..111
  are the 16 Finder bytes (FInfo for a file, DInfo for a folder —
  type@96, creator@100, finder flags@104, position@106, reserved or
  folder id@110); 112..115 a folder's scroll (vertical then
  horizontal); the rest of DXInfo is zero.  Bytes 124..127 are a
  CRC-32 over the first 124 bytes.
- A ``'file'`` record is followed by its data-fork block, its
  resource-fork block and its comment block, each present only when
  its size is nonzero.  A block is the payload, then a big-endian
  CRC-32 over the payload, then zero padding so payload + 4 + pad is
  a multiple of 128.  A ``'fold'`` record carries its children and is
  closed by a ``'----'`` record.
- Both CRCs are the same CRC-32: the normal (non-reflected) polynomial
  ``0x1EDC6F41``, initialised to 0, no final xor.

The whole byte stream may also be wrapped in an LZW (Unix ``compress``)
stream or an LZ4 frame — that is mar 0.2.0's compressed form.  This
reader handles the stored form only.  A stored archive opens here; a
``.Z``-wrapped one is read by the Unix compress module and comes out
as a single blob named from the file (no envelope chaining exists in
this library yet); an LZ4 frame is refused by name.

Folders are path components, not entries.  A folder's DInfo and scroll
are not carried (the entry model has nowhere to put folder Finder
info); a folder's comment block, if any, is verified and dropped.  A
file's comment block is verified, and carried on the entry as
``entry.comment``, cut at 255 bytes as the expanders write it.
"""

import struct

from .._core import Archive, Entry
from ..errors import CorruptError, UnsupportedError

MAR_MAGIC = 0x4D415280          # 'MAR\x80'
MAR_FILE = 0x66696C65           # 'file'
MAR_FOLDER = 0x666F6C64         # 'fold'
MAR_END = 0x2D2D2D2D            # '----'
HEADER_SIZE = 128
NAME_OFF = 8
NAME_CAP = 63
CRC_POLY = 0x1EDC6F41
MAX_DEPTH = 31
MAX_COMMENT = 255               # Get Info comment size, as the expanders write it
LZ4_MAGIC = b"\x04\x22\x4D\x18"


def _build_crc_table():
    table = []
    for i in range(256):
        reg = i << 24
        for _ in range(8):
            if reg & 0x80000000:
                reg = ((reg << 1) ^ CRC_POLY) & 0xFFFFFFFF
            else:
                reg = (reg << 1) & 0xFFFFFFFF
        table.append(reg)
    return table


_CRC_TABLE = _build_crc_table()


def mar_crc32(buf, crc=0):
    """The MAR CRC-32: MSB-first, polynomial 0x1EDC6F41, init 0, no xorout."""
    for byte in buf:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC_TABLE[((crc >> 24) ^ byte) & 0xFF]
    return crc


def _mac_roman(raw):
    try:
        return raw.decode("mac_roman")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _record_ok(hdr):
    return (struct.unpack_from(">I", hdr, 0)[0] == MAR_MAGIC
            and mar_crc32(hdr[:124]) == struct.unpack_from(">I", hdr, 124)[0])


def _block_pad(size):
    return (128 - ((size + 4) & 127)) & 127


def _read_block(data, pos, size, what, name):
    """Read one block; return ``(payload, new_pos)``.

    ``size`` of zero means there is no block at all.
    """
    if size == 0:
        return b"", pos
    end = pos + size
    if end + 4 > len(data):
        raise CorruptError(
            "MAR: the %s block of %r runs past the end of the archive"
            % (what, name))
    payload = data[pos:end]
    stored = struct.unpack_from(">I", data, end)[0]
    if mar_crc32(payload) != stored:
        raise CorruptError(
            "MAR: the %s block of %r fails its CRC-32" % (what, name))
    pos = end + 4
    pad = _block_pad(size)
    if pos + pad > len(data):
        raise CorruptError(
            "MAR: the %s block of %r is cut short in its padding"
            % (what, name))
    return payload, pos + pad


def _finder_info(hdr, is_folder):
    info = bytes(hdr[96:112])
    if is_folder:
        # DXInfo: DInfo (16) + frScroll (vertical then horizontal); the
        # rest is zero.
        return info + bytes(hdr[112:116]) + b"\0" * 12
    return info + b"\0" * 16


def _decode_record_name(hdr):
    raw = hdr[NAME_OFF:NAME_OFF + 64]
    length = raw[0]
    if length > NAME_CAP:
        length = NAME_CAP
    return _mac_roman(raw[1:1 + length])


def _parse_item(data, pos, path, depth, entries):
    if depth > MAX_DEPTH:
        raise CorruptError("MAR: folders nested deeper than %d" % MAX_DEPTH)
    if pos + HEADER_SIZE > len(data):
        if path:
            raise CorruptError("MAR: a folder is not terminated "
                               "(missing '----' record)")
        raise CorruptError("MAR: file is too small for a record")
    hdr = data[pos:pos + HEADER_SIZE]
    if not _record_ok(hdr):
        raise CorruptError("MAR: bad record at byte %d (magic or CRC)" % pos)
    rec_id = struct.unpack_from(">I", hdr, 4)[0]
    pos += HEADER_SIZE

    name = _decode_record_name(hdr)
    data_size, rsrc_size, comment_size = struct.unpack_from(">III", hdr, 72)
    file_flags = struct.unpack_from(">I", hdr, 84)[0]
    created, modified = struct.unpack_from(">II", hdr, 88)

    if rec_id == MAR_END:
        raise CorruptError("MAR: unexpected '----' (folder end) record")

    if rec_id == MAR_FOLDER:
        pos = _skip_block(data, pos, data_size)
        pos = _skip_block(data, pos, rsrc_size)
        pos = _skip_block(data, pos, comment_size)
        child_path = path + (name,)
        while True:
            if pos + HEADER_SIZE > len(data):
                raise CorruptError("MAR: folder %r is not terminated "
                                   "(missing '----' record)" % name)
            child = data[pos:pos + HEADER_SIZE]
            if _record_ok(child) and \
                    struct.unpack_from(">I", child, 4)[0] == MAR_END:
                pos += HEADER_SIZE
                break
            pos = _parse_item(data, pos, child_path, depth + 1, entries)
        return pos

    if rec_id != MAR_FILE:
        raise CorruptError("MAR: unknown record id 0x%08X at byte %d"
                           % (rec_id, pos - HEADER_SIZE))

    leaf = path + (name,)
    label = "/".join(leaf)
    data_fork, pos = _read_block(data, pos, data_size, "data fork", label)
    rsrc_fork, pos = _read_block(data, pos, rsrc_size, "resource fork", label)
    comment, pos = _read_block(data, pos, comment_size, "comment", label)

    entry = Entry(
        name=label,
        type=bytes(hdr[96:100]),
        creator=bytes(hdr[100:104]),
        finder_flags=struct.unpack_from(">H", hdr, 104)[0],
        locked=bool(file_flags & 0x00000001),
        protected=bool(file_flags & 0x00000002),
        created=created,
        modified=modified,
        finder_info=_finder_info(hdr, False),
        data_size=len(data_fork),
        resource_size=len(rsrc_fork),
    )
    entry._data = data_fork
    entry._rsrc = rsrc_fork
    if comment:
        entry.comment = comment[:MAX_COMMENT]
    entries.append(entry)
    return pos


def _skip_block(data, pos, size):
    """A folder record's blocks (present only in quirky writers): verify
    and discard."""
    if size == 0:
        return pos
    _, pos = _read_block(data, pos, size, "folder", "a folder")
    return pos


def open_data(data, password=None, filename=None):
    if data[:4] == LZ4_MAGIC:
        raise UnsupportedError(
            "MAR: the whole archive is an LZ4 frame; this reader "
            "handles the stored form only — decompress the frame first")
    if data[:2] == b"\x1f\x9d":
        raise UnsupportedError(
            "MAR: the whole archive is LZW-compressed (Unix compress); "
            "this reader handles the stored form only — decompress it "
            "first (the Unix compress module reads it)")
    if len(data) < HEADER_SIZE:
        raise CorruptError("MAR: file is too small")
    if not _record_ok(data[:HEADER_SIZE]):
        raise CorruptError("MAR: bad record at byte 0 (magic or CRC)")

    archive = Archive()
    archive.format = "MAR"
    entries = []
    pos = _parse_item(data, 0, (), 1, entries)
    if pos != len(data):
        raise CorruptError(
            "MAR: %d trailing bytes after the root item" % (len(data) - pos))
    archive.entries = entries
    return archive


def probe(data):
    if len(data) < HEADER_SIZE:
        return 0
    if struct.unpack_from(">I", data, 0)[0] != MAR_MAGIC:
        return 0
    if _record_ok(data[:HEADER_SIZE]):
        return 90
    return 45
