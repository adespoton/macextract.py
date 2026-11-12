"""StuffIt 5+ (.sit) — Aladdin's second archiver.

Archive header, big-endian:

   0  80  banner: ``StuffIt (c)1997-`` then four arbitrary year digits,
         `` Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/``
         and CR LF — exactly 80 bytes
  80  2   unknown
  82  1   archive version (5)
  83  1   flags: 0x10 a 14-byte block follows the fixed header; 0x20 a
         four-byte block (comment length, style-scrap length); 0x80
         encrypted archive — after those blocks one byte 5 then the
         five-byte password hash ``MD5(MD5(password)[:5])[:5]``
  84  4   total archive size (advisory; not checked)
  88  4   unknown
  92  2   entry count (the walk adds each folder's children to it)
  94  4   offset of the first entry
  98  2   header CRC (algorithm not established; not checked)

The published table gives offset 84 twice and then jumps to 86; 92 and
94 are what reads the real archives, and what the other published copy
of the same table says.  Neither archive nor entry header CRC is
checked, same as the reference implementations.

Then the entries, in walk order (each header is at the previous
entry's end, forks included — not at the ``next entry`` offset the
published table cites).  Entry header, big-endian:

   0  4   identifier ``0xA5A5A5A5``
   4  1   entry version (1 or 3)
   6  2   header size
   9  1   flags: 0x40 folder, 0x20 this entry is encrypted
  10  4   created; 14  4  modified (Mac epoch seconds)
  18  4   previous entry offset; 22  4  next; 26  4  parent folder offset
  30  2   name length; 32  2  entry header CRC (not checked)
  34  4   data fork length; 38  4  stored length; 42  2  fork CRC-16;
         44  2  unknown
  folder: 46  2  number of direct children.  A folder whose data fork
         length is ``0xffffffff`` is the marker entry that follows
         every folder: skipped, and it does not count against the
         entry count.  A real folder ends right after its second block
         and has no forks.
  file:   46  1  method; 47  1  password-key length (0 or 5); 48  the
         key bytes

then the name — UTF-8 here, where StuffIt classic is MacRoman — then,
if header space remains, the comment (u16 length, u16 style length,
text), then the second block: u16 flags (bit 0 = resource fork
present), u16 CRC-16/ARC of the block with its own two bytes zeroed
(plus the resource fork's key bytes when there is one) — the gate
that makes the rest of the block trustworthy — then type, creator,
Finder flags and filler: 36 bytes at entry version 1, 32 at version 3.
With a resource fork present: its length, stored length, CRC-16, two
unknown bytes, method, key length, key.  Forks follow the header,
resource fork first, then data.

A folder path is the parent-offset chain, not the walk's order: each
folder records its own header offset, children name it at offset 26.

Fork CRCs are CRC-16/ARC — the parent project's behavior on real
archives, same as StuffIt classic's; the wiki's CCITT claim disagrees
with it.  Methods 0, 1, 2, 3 and 13 decode (the classic codecs);
method 15 (Arsenic) and 14 and the rest are refused by name.

Encryption is per entry (flag 0x20): each keyed fork is RC4 under
``MD5(password)[:5]`` plus the fork's own five clear key bytes, with
the password graded against the archive header's hash first —
measured by the parent project against archives Aladdin's own
software wrote.  PasswordRequiredError when no password was supplied,
BadPasswordError for the wrong one.
"""

import hashlib
import struct

from .._core import Archive, Entry
from .._crc16 import crc16_arc
from .._huffman import decode as _huffman_decode
from .._lzw import lzw_decompress
from .._rle90 import rle90_decode
from .._rc4 import rc4
from .._sit13 import sit13_decode
from ..errors import (
    BadPasswordError,
    CorruptError,
    PasswordRequiredError,
    UnsupportedError,
)

ARCHIVE_HEADER = 100
ENTRY_ID = 0xA5A5A5A5
DATALEN_NONE = 0xFFFFFFFF
FOLDER = 0x40
ENTRY_CRYPTED = 0x20
ARCH_14BYTES = 0x10
ARCH_COMMENT = 0x20
ARCH_CRYPTED = 0x80
KEYLEN = 5

BANNER = (b"StuffIt (c)1997-" + b"\xff\xff\xff\xff"
          + b" Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\r\n")

_SUPPORTED = (0, 1, 2, 3, 13)


def _looks_like(data):
    if len(data) < ARCHIVE_HEADER or len(data) < len(BANNER):
        return False
    return all(a == b or b == 0xFF for a, b in zip(data, BANNER))


def probe(data):
    if not _looks_like(data):
        return 0
    return 90


def _password_bytes(password):
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)


def _md5_5(data):
    return hashlib.md5(data, usedforsecurity=False).digest()[:KEYLEN]


def _decode_fork(method, stored, length, name, label):
    method &= 0x0F
    if method == 0:
        if len(stored) < length:
            raise CorruptError(
                "StuffIt 5: %s fork of %r is shorter than its length"
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
    raise UnsupportedError(
        "StuffIt 5: method %d compression is not supported" % method)


def _read_fork(data, offset, stored_len, method, length, want_crc, key,
               name, label):
    if length == 0:
        return b""
    stored = data[offset:offset + stored_len]
    if key:
        stored = rc4(stored, key)
    decoded = _decode_fork(method, stored, length, name, label)
    if crc16_arc(decoded) != want_crc:
        raise CorruptError(
            "StuffIt 5: %s fork CRC mismatch for %r" % (label, name))
    return decoded


def _parse(data, password):
    if not _looks_like(data):
        raise UnsupportedError("StuffIt 5: not a StuffIt 5 archive")
    if data[82] != 5:
        raise UnsupportedError(
            "StuffIt 5: archive version %d is not supported" % data[82])
    flags = data[83]
    count = struct.unpack_from(">H", data, 92)[0]
    pos = struct.unpack_from(">I", data, 94)[0]

    pwhash = None
    if flags & ARCH_CRYPTED:
        at = ARCHIVE_HEADER
        if flags & ARCH_14BYTES:
            at += 14
        if flags & ARCH_COMMENT:
            at += 4
        if at + 1 + KEYLEN > len(data):
            raise CorruptError(
                "StuffIt 5: the archive's password hash runs past the end")
        if data[at] != KEYLEN:
            raise UnsupportedError(
                "StuffIt 5: password hash length %d is not supported"
                % data[at])
        pwhash = bytes(data[at + 1:at + 1 + KEYLEN])

    archive_key = None
    dirs = {}
    entries = []
    processed = 0
    while processed < count:
        if pos + 48 > len(data):
            raise CorruptError(
                "StuffIt 5: entry at offset %d runs past the end" % pos)
        if struct.unpack_from(">I", data, pos)[0] != ENTRY_ID:
            raise CorruptError(
                "StuffIt 5: no entry identifier at offset %d" % pos)

        entry_version = data[pos + 4]
        headersize = struct.unpack_from(">H", data, pos + 6)[0]
        headerend = pos + headersize
        eflags = data[pos + 9]
        created = struct.unpack_from(">I", data, pos + 10)[0]
        modified = struct.unpack_from(">I", data, pos + 14)[0]
        diroffs = struct.unpack_from(">I", data, pos + 26)[0]
        namelen = struct.unpack_from(">H", data, pos + 30)[0]
        datalen = struct.unpack_from(">I", data, pos + 34)[0]
        datacomp = struct.unpack_from(">I", data, pos + 38)[0]
        datacrc = struct.unpack_from(">H", data, pos + 42)[0]
        encrypted = eflags & ENTRY_CRYPTED
        hpos = pos + 46

        datamethod = 0
        datakey = None
        if eflags & FOLDER:
            dirfiles = struct.unpack_from(">H", data, hpos)[0]
            hpos += 2
            if datalen == DATALEN_NONE:
                # The marker entry after every folder: skipped, and it
                # does not count against the entry total.  It must
                # still advance the walk.
                if headerend <= pos:
                    raise CorruptError(
                        "StuffIt 5: the folder marker at offset %d does "
                        "not advance the walk" % pos)
                count += 1
                processed += 1
                pos = headerend
                continue
        else:
            datamethod = data[hpos]
            passlen = data[hpos + 1]
            hpos += 2
            if passlen:
                if not encrypted or not datalen or passlen != KEYLEN:
                    raise CorruptError(
                        "StuffIt 5: password key data on the entry at "
                        "offset %d that does not take one" % pos)
                datakey = bytes(data[hpos:hpos + passlen])
                hpos += passlen

        if hpos + namelen > len(data):
            raise CorruptError(
                "StuffIt 5: the name at offset %d runs past the end" % pos)
        name = data[hpos:hpos + namelen].decode("utf-8", errors="replace")
        hpos += namelen

        if hpos < headerend:
            if hpos + 4 > len(data):
                raise CorruptError(
                    "StuffIt 5: the comment at offset %d runs past the end"
                    % pos)
            commentlen = struct.unpack_from(">H", data, hpos)[0]
            hpos += 4 + commentlen
            if hpos > len(data):
                raise CorruptError(
                    "StuffIt 5: the comment at offset %d runs past the end"
                    % pos)

        # Second block: flags, its own CRC, then the Finder info —
        # 36 bytes at entry version 1, 32 at version 3.
        blen = 36 if entry_version == 1 else 32
        if hpos + blen > len(data):
            raise CorruptError(
                "StuffIt 5: the entry header at offset %d runs past the end"
                % pos)
        block = bytes(data[hpos:hpos + blen])
        flags2 = struct.unpack_from(">H", block, 0)[0]
        blockcrc = struct.unpack_from(">H", block, 2)[0]
        type_ = bytes(block[4:8])
        creator = bytes(block[8:12])
        finder_flags = struct.unpack_from(">H", block, 12)[0]
        hpos += blen

        rsrclen = rsrccomp = rsrccrc = rsrcmethod = 0
        rsrckey = None
        rsrc_at = hpos
        if flags2 & 1:
            if hpos + 14 > len(data):
                raise CorruptError(
                    "StuffIt 5: the resource fork header at offset %d runs "
                    "past the end" % pos)
            rsrclen, rsrccomp, rsrccrc = struct.unpack_from(">IIH", data, hpos)
            rsrcmethod = data[hpos + 12]
            passlen = data[hpos + 13]
            hpos += 14
            if passlen:
                if not encrypted or not rsrclen or passlen != KEYLEN:
                    raise CorruptError(
                        "StuffIt 5: password key data on the entry at "
                        "offset %d that does not take one" % pos)
                rsrckey = bytes(data[hpos:hpos + passlen])
                hpos += passlen
        datastart = hpos

        parent = dirs.get(diroffs)
        full = (parent + "/" + name) if parent else name

        if eflags & FOLDER:
            dirs[pos] = full
            count += dirfiles
            processed += 1
            pos = datastart
            continue

        if encrypted:
            if pwhash is None:
                raise UnsupportedError(
                    "StuffIt 5: the entry %r is encrypted and the archive "
                    "carries no password hash" % name)
            if archive_key is None:
                if password is None:
                    raise PasswordRequiredError(
                        "StuffIt 5: the entry %r is encrypted" % name)
                archive_key = _md5_5(_password_bytes(password))
                if _md5_5(archive_key) != pwhash:
                    raise BadPasswordError("StuffIt 5: wrong password")

        if datastart + rsrccomp + datacomp > len(data):
            raise CorruptError(
                "StuffIt 5: forks of %r run past the end of the data" % name)

        finder_info = None
        if entry_version == 1:
            # The block's own CRC decides whether the Finder info the
            # rest of the block carries is trusted; type, creator and
            # Finder flags stand either way.
            check = bytearray(block)
            check[2] = check[3] = 0
            if flags2 & 1:
                check += data[rsrc_at:rsrc_at + 14]
            crc = crc16_arc(bytes(check))
            if rsrckey:
                crc = crc16_arc(rsrckey, crc)
            if crc == blockcrc:
                finder_info = bytes(block[4:36])

        rsrc = b""
        if flags2 & 1:
            rsrc = _read_fork(
                data, datastart, rsrccomp, rsrcmethod, rsrclen, rsrccrc,
                (archive_key + rsrckey) if rsrckey else None,
                name, "resource")
        payload = _read_fork(
            data, datastart + rsrccomp, datacomp, datamethod, datalen,
            datacrc, (archive_key + datakey) if datakey else None,
            name, "data")

        entry = Entry(
            name=full,
            type=type_,
            creator=creator,
            finder_flags=finder_flags,
            created=created,
            modified=modified,
            finder_info=finder_info,
        )
        entry._data = payload
        entry._rsrc = rsrc
        entry.data_size = len(payload)
        entry.resource_size = len(rsrc)
        entries.append(entry)
        processed += 1
        pos = datastart + rsrccomp + datacomp

    archive = Archive()
    archive.format = "StuffIt 5"
    archive.entries = entries
    return archive


def open_data(data, password=None, filename=None):
    return _parse(data, password)
