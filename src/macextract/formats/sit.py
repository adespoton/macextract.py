"""StuffIt classic (.sit) — the original Macintosh archiver.

Archive header, 22 bytes, big-endian:

   0  4   magic: ``SIT!`` (or an installer word: ``ST`` + ``in`` or
         ``i``-digit, or two digits — always with ``rLau`` at 10)
   4  2   file count (advisory; the walk does not trust it)
   6  4   total archive size
  10  4   ``rLau``
  14  1   version
  15  7   unknown

Then a series of 112-byte file headers, each followed by its fork
bytes — resource fork first, then data fork; the next header follows
both.  Header, all big-endian:

   0  1   resource fork method; 1  1  data fork method.  Low four
         bits: compression (0 stored, 1 RLE-90, 2 LZW 14-bit, 3
         serialized Huffman, 13 LZ + Huffman, 15 Arsenic; 6/8 and
         friends are not implemented).  0x40: an Optimizer module ran first, its
         id at 108 (resource) / 106 (data); id 255 has nothing to
         undo and the bytes stand as stored.  0x80 / 0x10: encrypted
         (``NewDE``), encryptor id at 109 / 107.  32 / 33: this
         record instead marks the start / end of a folder.
   2  1   name length (only 31 of the name field is used here)
   3  63  name
  34  2   CRC-16 of bytes 2..33 — the gate that makes the flags at 36
         trustworthy
  36  2   flags; bit 15 = locked
  66  4   type; 70  4  creator; 74  2  Finder flags
  76  4   created; 80  4  modified (Mac epoch seconds)
  84  4   resource fork length;   88  4  data fork length
  92  4   resource fork stored bytes; 96  4  data fork stored bytes
 100  2   resource fork CRC-16 (of the decoded bytes)
 102  2   data fork CRC-16
 110  2   header CRC-16 (over bytes 0..109)

Every CRC is CRC-16/ARC (reflected polynomial 0xA001; check value
0xBB3D over ``123456789``).  Folder records are path components only —
entries inside them carry the path prefix.  Encrypted forks (every
cipher, PassLock included) and Optimizer ids other than 255 are
refused by name; no password is ever asked for, because none can be
used yet.
"""

import struct

from .._core import Archive, Entry
from .._arsenic import arsenic_decode
from .._crc16 import crc16_arc
from .._huffman import decode as _huffman_decode
from .._lzw import lzw_decompress
from .._rle90 import rle90_decode
from .._sit13 import sit13_decode
from ..errors import CorruptError, UnsupportedError

ARCHIVE_HEADER = 22
HEADER_SIZE = 112
MAX_DEPTH = 31          # path components the folder stack may reach


def _looks_like(data):
    """The probe's test, also re-run before parsing: ``rLau`` at 10
    plus a known magic word at 0."""
    if len(data) < 14 or data[10:14] != b"rLau":
        return False
    if data[:4] == b"SIT!":
        return True
    if data[:2] == b"ST":
        if data[2:4] == b"in":
            return True
        if data[2] == ord("i") and 0x30 <= data[3] <= 0x39:
            return True
        if 0x30 <= data[2] <= 0x39 and 0x30 <= data[3] <= 0x39:
            return True
    return False


def probe(data):
    if not _looks_like(data):
        return 0
    return 90 if data[:4] == b"SIT!" else 70


def _decode_fork(method, stored, length, name, label):
    if method == 0:
        if len(stored) < length:
            raise CorruptError(
                "StuffIt: %s fork of %r is shorter than its length"
                % (label, name))
        return stored[:length]
    if method == 1:
        return rle90_decode(stored, length)
    if method == 2:
        return lzw_decompress(stored, length, maxbits=14, blockmode=True)
    if method == 3:
        return _huffman_decode(stored, length)[0]
    if method == 13:
        return sit13_decode(stored, length)
    if method == 15:
        return arsenic_decode(stored, length)
    raise UnsupportedError(
        "StuffIt: method %d compression is not supported" % method)


def _read_fork(data, offset, stored_len, method, length, want_crc,
               name, label):
    if length == 0:
        return b""
    decoded = _decode_fork(method, data[offset:offset + stored_len],
                           length, name, label)
    # Method 15 carries its own CRC-32, checked inside the decoder; the
    # header's CRC-16 field means nothing for it (it is set to zero).
    if method != 15 and crc16_arc(decoded) != want_crc:
        raise CorruptError(
            "StuffIt: %s fork CRC mismatch for %r" % (label, name))
    return decoded


def _parse(data):
    if not _looks_like(data):
        raise UnsupportedError("StuffIt: not a StuffIt archive")
    totalsize = struct.unpack_from(">I", data, 6)[0]
    if totalsize < ARCHIVE_HEADER:
        raise CorruptError(
            "StuffIt: archive size field says %d bytes" % totalsize)
    if totalsize > len(data):
        raise CorruptError(
            "StuffIt: archive claims %d bytes but the data has %d"
            % (totalsize, len(data)))

    entries = []
    path = []
    pos = ARCHIVE_HEADER
    while pos + HEADER_SIZE <= totalsize:
        hdr = data[pos:pos + HEADER_SIZE]
        if crc16_arc(hdr[:110]) != struct.unpack_from(">H", hdr, 110)[0]:
            # Without a valid header there is no way to find the next
            # entry, so this is fatal rather than skippable.
            raise CorruptError(
                "StuffIt: entry header CRC mismatch at offset %d" % pos)
        rmeth, dmeth = hdr[0], hdr[1]
        namelen = min(hdr[2], 31)
        name = hdr[3:3 + namelen].decode("mac_roman", errors="replace")

        if (rmeth & 0x6F) == 0x20 or (dmeth & 0x6F) == 0x20:
            if len(path) >= MAX_DEPTH:
                raise CorruptError(
                    "StuffIt: folder nesting deeper than %d" % MAX_DEPTH)
            path.append(name)
            pos += HEADER_SIZE
            continue
        if (rmeth & 0x6F) == 0x21 or (dmeth & 0x6F) == 0x21:
            if path:
                path.pop()
            pos += HEADER_SIZE
            continue

        start = pos + HEADER_SIZE
        rlen, dlen, rcomp, dcomp = struct.unpack_from(">IIII", hdr, 84)
        if start + rcomp + dcomp > len(data):
            raise CorruptError(
                "StuffIt: forks of %r run past the end of the data" % name)

        # An encryptor outranks the optimizer: one entry can carry
        # both, and nothing can get as far as running the optimizer.
        for meth, flen, opt_off, label in (
                (rmeth, rlen, 108, "resource"),
                (dmeth, dlen, 106, "data")):
            if not flen:
                continue
            if meth & 0x90:            # 0x80 encrypted, or 0x10 NewDE
                raise UnsupportedError(
                    "StuffIt: the %s fork of %r is encrypted; no cipher "
                    "can read it" % (label, name))
            if meth & 0x40 and hdr[opt_off] != 255:
                raise UnsupportedError(
                    "StuffIt: the %s fork of %r was optimized by module "
                    "%d; that optimizer is not supported"
                    % (label, name, hdr[opt_off]))

        rsrc_crc, data_crc = struct.unpack_from(">HH", hdr, 100)
        rsrc = _read_fork(data, start, rcomp, rmeth & 0x0F, rlen,
                          rsrc_crc, name, "resource")
        payload = _read_fork(data, start + rcomp, dcomp, dmeth & 0x0F,
                             dlen, data_crc, name, "data")

        name_crc_ok = (crc16_arc(hdr[2:34])
                       == struct.unpack_from(">H", hdr, 34)[0])
        entry = Entry(
            name="/".join(path + [name]),
            type=bytes(hdr[66:70]),
            creator=bytes(hdr[70:74]),
            finder_flags=struct.unpack_from(">H", hdr, 74)[0],
            locked=name_crc_ok and bool(hdr[36] & 0x80),
            created=struct.unpack_from(">I", hdr, 76)[0],
            modified=struct.unpack_from(">I", hdr, 80)[0],
            finder_info=bytes(hdr[66:74]) + bytes(hdr[74:76]) + b"\0" * 22,
        )
        entry._data = payload
        entry._rsrc = rsrc
        entry.data_size = len(payload)
        entry.resource_size = len(rsrc)
        entries.append(entry)
        pos = start + rcomp + dcomp

    archive = Archive()
    archive.format = "StuffIt"
    archive.entries = entries
    return archive


def open_data(data, password=None, filename=None):
    # Encryption is refused by name above; no password can unlock an
    # entry until a cipher is implemented, so none is asked for.
    return _parse(data)
