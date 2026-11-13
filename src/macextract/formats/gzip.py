"""gzip (.gz) reader — RFC 1952.

A gzip member is::

    1f 8b CM FLG MTIME(4, LE) XFL OS
    [FEXTRA]   if FLG & 0x04 — u16 LE byte count, then that many bytes
    [FNAME]    if FLG & 0x08 — NUL-terminated original file name
    [FCOMMENT] if FLG & 0x10 — NUL-terminated comment
    [FHCRC]    if FLG & 0x02 — two bytes, the low 16 bits of CRC-32 of
               the header up to this point
    <raw deflate stream>
    CRC32(4, LE)  of the UNCOMPRESSED member data
    ISIZE(4, LE)  uncompressed member size mod 2**32

CM must be 8 (deflate); any other method is refused by name.  The
``filename`` hint names the single entry, with a trailing ``.gz``
stripped — as the C reference's Unix compress reader and this
library's .Z module derive the name.  When no hint is given the
entry is called ``uncompressed``.

Concatenated members: RFC 1952 §2.2 and gzip(1) both define the
payload of a multi-member file as the concatenation of the members'
payloads.  This reader supports that — each member is decoded and
checked (CRC-32 and ISIZE) in turn, and one entry holds the whole
concatenated payload, exactly what ``gzip -dc`` writes.  A truncated
or corrupt member fails the open, it does not yield partial output.
"""

import os
import zlib

from .._core import Archive, Entry
from ..errors import CorruptError, UnsupportedError

OUTPUT_CAP = 1024 * 1024 * 1024  # 1 GiB ceiling; gzip sizes are mod 2**32

FLG_FHCRC = 0x02
FLG_FEXTRA = 0x04
FLG_FNAME = 0x08
FLG_FCOMMENT = 0x10
FLG_RESERVED = 0xE0


def probe(data):
    if len(data) < 3:
        return 0
    if data[0] != 0x1F or data[1] != 0x8B:
        return 0
    if data[2] != 8:
        return 0
    return 90


def _read_member(data, offset, number):
    """Decode one member starting at ``offset``.

    Returns ``(payload, next_offset)``.  Raises CorruptError /
    UnsupportedError.
    """
    start = offset
    if len(data) - offset < 10:
        raise CorruptError(
            "gzip: member %d at offset %d is truncated (%d bytes left)"
            % (number, offset, len(data) - offset))
    if data[offset] != 0x1F or data[offset + 1] != 0x8B:
        raise CorruptError(
            "gzip: member %d at offset %d does not start with the"
            " 1f 8b magic" % (number, offset))
    method = data[offset + 2]
    if method != 8:
        raise UnsupportedError(
            "gzip: member %d uses compression method %d; only 8 (deflate)"
            " is supported" % (number, method))
    flg = data[offset + 3]
    if flg & FLG_RESERVED:
        raise CorruptError(
            "gzip: member %d sets reserved flag bits 0x%02x" % (number, flg & FLG_RESERVED))
    offset += 10  # magic(2) CM FLG MTIME(4) XFL OS
    if flg & FLG_FEXTRA:
        if len(data) - offset < 2:
            raise CorruptError("gzip: member %d ends inside FEXTRA" % number)
        xlen = data[offset] | (data[offset + 1] << 8)
        offset += 2
        if len(data) - offset < xlen:
            raise CorruptError("gzip: member %d ends inside FEXTRA" % number)
        offset += xlen
    if flg & FLG_FNAME:
        end = data.find(b"\0", offset)
        if end == -1:
            raise CorruptError("gzip: member %d ends inside FNAME" % number)
        offset = end + 1
    if flg & FLG_FCOMMENT:
        end = data.find(b"\0", offset)
        if end == -1:
            raise CorruptError("gzip: member %d ends inside FCOMMENT" % number)
        offset = end + 1
    if flg & FLG_FHCRC:
        if len(data) - offset < 2:
            raise CorruptError("gzip: member %d ends inside FHCRC" % number)
        header_crc = data[offset] | (data[offset + 1] << 8)
        actual = zlib.crc32(data[start:offset]) & 0xFFFF
        if actual != header_crc:
            raise CorruptError(
                "gzip: member %d header CRC mismatch (0x%04x != 0x%04x)"
                % (number, header_crc, actual))
        offset += 2

    deflate_start = offset
    decompressor = zlib.decompressobj(-15)
    try:
        out = decompressor.decompress(data[offset:], OUTPUT_CAP + 1)
        out += decompressor.flush()
    except zlib.error as error:
        raise CorruptError(
            "gzip: member %d deflate stream is broken (%s)" % (number, error)
        ) from error
    if len(out) > OUTPUT_CAP:
        raise CorruptError(
            "gzip: member %d exceeds the 1 GiB output ceiling" % number)
    if not decompressor.eof:
        raise CorruptError(
            "gzip: member %d deflate stream ends before the input does"
            " or the file is truncated" % number)
    consumed = len(data) - offset - len(decompressor.unused_data)
    offset += consumed

    if len(data) - offset < 8:
        raise CorruptError(
            "gzip: member %d is missing its CRC-32/ISIZE trailer" % number)
    crc, isize = int.from_bytes(data[offset:offset + 4], "little"), \
        int.from_bytes(data[offset + 4:offset + 8], "little")
    if zlib.crc32(out) != crc:
        raise CorruptError("gzip: member %d CRC-32 mismatch" % number)
    if len(out) & 0xFFFFFFFF != isize:
        raise CorruptError(
            "gzip: member %d ISIZE mismatch (%d mod 2**32 != %d)"
            % (number, len(out) & 0xFFFFFFFF, isize))
    return out, offset + 8


def open_data(data, password=None, filename=None):
    if password is not None:
        # gzip has no encryption; say so rather than decode with a
        # password silently ignored.
        raise UnsupportedError("gzip: gzip files are not encrypted")
    if len(data) < 10:
        raise CorruptError("gzip: file is too small")
    chunks = []
    offset = 0
    number = 0
    while offset < len(data):
        number += 1
        chunk, offset = _read_member(data, offset, number)
        chunks.append(chunk)
    total = sum(len(c) for c in chunks)
    if total > OUTPUT_CAP:
        raise CorruptError("gzip: concatenated payload exceeds the 1 GiB ceiling")
    payload = b"".join(chunks)

    archive = Archive()
    archive.format = "gzip"
    if filename and isinstance(filename, str):
        leaf = os.path.basename(filename)
        lower = leaf.lower()
        for suffix in (".gz",):
            if lower.endswith(suffix):
                leaf = leaf[:-len(suffix)]
                break
        name = leaf or "uncompressed"
    else:
        name = "uncompressed"
    entry = Entry(name=name)
    entry._data = payload
    entry.data_size = len(payload)
    entry.resource_size = 0
    archive.entries.append(entry)
    return archive
