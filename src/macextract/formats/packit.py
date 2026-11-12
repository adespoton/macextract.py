"""PackIt (.pit) — Harry Chesley's classic archive.

A concatenated series of subfiles, each opening with a four-byte type
word, ending with ``PEnd``:

  PMag — stored
  PMa4 — bit-serialized Huffman coded (see macextract._huffman); the
         coded stream is the whole subfile — 94-byte header, data fork,
         resource fork, 2-byte CRC — under one tree
  PMa5 — Huffman coded and encrypted; refused with a clear error, the
         cipher is not described anywhere we can rely on
  PEnd — end of file

Subfile header, 94 bytes, all big-endian except as noted:

   0  1   name length, 1..63
   1  63  name (fixed field)
  64  4   type
  68  4   creator
  72  1   Finder flags
  73  1   filler
  74  2   locked, nonzero if set
  76  4   data fork length
  80  4   resource fork length
  84  4   created, seconds since 1904-01-01
  88  4   modified
  92  2   CRC of the header (polynomial not established; not checked)

then the data fork, the resource fork, and a trailing 2-byte CRC over
the forks (also not checked).

PackIt files may circulate inside a MacBinary envelope; the library
opens that layer first and this reader sees the bare stream.
"""

import struct

from .._core import Archive, Entry
from .._huffman import HuffmanDecoder
from ..errors import CorruptError, UnsupportedError

TYPE_STORED = b"PMag"
TYPE_HUFFMAN = b"PMa4"
TYPE_ENCRYPTED = b"PMa5"
TYPE_END = b"PEnd"

HEADER_SIZE = 94
TAIL_CRC_SIZE = 2


def _parse_header(buf, offset=0):
    name_len = buf[offset]
    if not 1 <= name_len <= 63:
        raise CorruptError("PackIt: name length %d out of range" % name_len)
    name_bytes = buf[offset + 1: offset + 64][:name_len]
    file_type = buf[offset + 64: offset + 68]
    creator = buf[offset + 68: offset + 72]
    flags = buf[offset + 72] << 8
    locked = struct.unpack_from(">H", buf, offset + 74)[0] != 0
    data_len, rsrc_len = struct.unpack_from(">II", buf, offset + 76)
    created, modified = struct.unpack_from(">II", buf, offset + 84)
    try:
        name = name_bytes.decode("mac_roman")
    except UnicodeDecodeError:
        name = name_bytes.decode("mac_roman", errors="replace")
    return Entry(
        name=name,
        type=file_type,
        creator=creator,
        finder_flags=flags,
        locked=locked,
        created=created,
        modified=modified,
        finder_info=file_type + creator + struct.pack(">H", flags) + b"\0" * 22,
        data_size=data_len,
        resource_size=rsrc_len,
    ), data_len, rsrc_len


def _finish_entry(entry, data, rsrc):
    entry._data = data
    entry._rsrc = rsrc
    entry.data_size = len(data)
    entry.resource_size = len(rsrc)
    return entry


def _parse(data):
    if len(data) < 4:
        raise CorruptError("PackIt: file too small for a type word")
    entries = []
    offset = 0
    saw_end = False
    while offset + 4 <= len(data):
        word = data[offset:offset + 4]
        if word == TYPE_END:
            saw_end = True
            break
        if word == TYPE_ENCRYPTED:
            raise UnsupportedError(
                "PackIt: PMa5 subfiles are encrypted and are not supported")
        if word == TYPE_STORED:
            entry, data_len, rsrc_len = _parse_header(data, offset + 4)
            fork_start = offset + 4 + HEADER_SIZE
            fork_end = fork_start + data_len + rsrc_len + TAIL_CRC_SIZE
            if fork_end > len(data):
                raise CorruptError("PackIt: subfile is truncated")
            forks = data[fork_start:fork_start + data_len + rsrc_len]
            entries.append(_finish_entry(entry, forks[:data_len], forks[data_len:]))
            offset = fork_end
            continue
        if word == TYPE_HUFFMAN:
            coded_start = offset + 4
            stream, used_end = _decode_coded_subfile(data, coded_start)
            entry, data_len, rsrc_len = _parse_header(stream, 0)
            body = stream[HEADER_SIZE:]
            need = data_len + rsrc_len + TAIL_CRC_SIZE
            if len(body) < need:
                raise CorruptError("PackIt: coded subfile decoded short")
            forks = body[:data_len + rsrc_len]
            entries.append(_finish_entry(entry, forks[:data_len], forks[data_len:]))
            offset = used_end
            continue
        raise CorruptError("PackIt: unknown type word %r" % word)
    if not saw_end:
        raise CorruptError("PackIt: missing PEnd")
    archive = Archive()
    archive.format = "PackIt"
    archive.entries = entries
    return archive


def _decode_coded_subfile(data, coded_start):
    """Decode one PMa4 subfile: one tree codes the whole stream — header,
    forks and tail CRC — so the header comes out first (94 symbols), its
    dlen/rlen fields size the rest, and the declarations below read what
    remains under the same tree."""
    decoder = HuffmanDecoder(data, coded_start)
    header = decoder.decode(HEADER_SIZE)
    entry, data_len, rsrc_len = _parse_header(header, 0)
    remaining = data_len + rsrc_len + TAIL_CRC_SIZE
    body = decoder.decode(remaining)
    return header + body, decoder.next_byte_offset


def probe(data):
    head = data[:4]
    if head in (TYPE_STORED, TYPE_HUFFMAN, TYPE_ENCRYPTED):
        return 80
    if head == TYPE_END:
        return 40  # an empty PackIt; valid but bare
    return 0


def open_data(data, password=None, filename=None):
    # PackIt encryption is not password-based in any spec we carry; a
    # supplied password does not unlock a PMa5 subfile.
    return _parse(data)
