"""zip reader — APPNOTE local-file-header stream; the central
directory is the index.

The archive layout this reader uses::

    Local file header   PK\\x03\\x04   (see below), then the raw or
                                        compressed bytes of the member
    Central directory   PK\\x01\\x02   one record per member, carrying
                                        the CRC-32, sizes, method, flags,
                                        the name's authoritative form and
                                        the offset of the local header
    End of central dir  PK\\x05\\x06   where the directory starts and how
                                        many records it holds

Each member's data is located through the central directory's local
header offset (the directory holds the authoritative sizes; a local
header whose general-purpose bit 3 is set carries zero there and the
real lengths live in the data descriptor that follows the data).
The central directory is also where multi-disk and ZIP64 are detected
and refused by name.

Supported: method 0 (stored) and method 8 (deflate, raw RFC 1951 —
``zlib`` with ``wbits=-15``).  Every other method is refused by name
(``bzip2`` for 10/0x0C, ``LZMA`` for 14/0x0E, and so on); members
declaring an unknown compression method fail likewise.

Refused by name:

- multi-disk / spanned archives (any disk number other than 0 in the
  EOCD or a central record, or an entry on another disk);
- ZIP64 (sizes, offsets or entry counts of 0xFFFF/0xFFFFFFFF, or a
  0x0001 extra field on a central record or local header);
- members encrypted with the classic ZIP scheme or strong encryption
  (bit 0x0001 / 0x0040 of the general-purpose flags) — a member so
  flagged raises PasswordRequiredError, since the archive demands a
  password this library has no notion of asking for mid-open; strong
  encryption raises UnsupportedError by name.

CRC-32 of every member is checked against the central directory's
value, and the decompressed size must match the declared size exactly.
The 1 GiB per-member output ceiling of the .Z reader applies too.

Names come from the central directory; flag bit 0x0800 means UTF-8,
otherwise the bytes are CP437 (APPNOTE's default).  Names ending in
``/`` (and members whose DOS/UNIX attribute marks a directory) are
skipped: the extract path creates directories from the file entries'
paths.  Names are sanitised at extraction time by the shared
``_sanitize_name``.
"""

import datetime
import struct
import zlib

from .._core import MAC_EPOCH_OFFSET, Archive, Entry
from ..errors import CorruptError, PasswordRequiredError, UnsupportedError

OUTPUT_CAP = 1024 * 1024 * 1024  # 1 GiB per member, as for .Z

LOCAL_SIG = b"PK\x03\x04"
CENTRAL_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"

METHOD_STORED = 0
METHOD_DEFLATE = 8
_METHOD_NAMES = {
    1: "Shrink",
    2: "Reduce level 1",
    3: "Reduce level 2",
    4: "Reduce level 3",
    5: "Reduce level 4",
    6: "Implode",
    7: "Tokenize (reserved)",
    9: "Deflate64",
    10: "PKWARE DCL Imploding",
    12: "bzip2",
    14: "LZMA",
    16: "IBM Enhanced Deflate",
    18: "IBM TERSE",
    19: "IBM LZ77 z",
    93: "Zstandard",
    95: "xz",
    96: "JPEG",
    97: "WavPack",
    98: "PPMd",
}

FLAG_ENCRYPTED = 0x0001
FLAG_STRONG_ENCRYPT = 0x0040
FLAG_UTF8 = 0x0800

EOCD_SIZE = 22
ZIP64_SENTINEL_16 = 0xFFFF
ZIP64_SENTINEL_32 = 0xFFFFFFFF
EXTRA_ZIP64 = 0x0001


def probe(data):
    if len(data) < EOCD_SIZE:
        return 0
    if data[:4] not in (LOCAL_SIG, EOCD_SIG):
        return 0
    # An EOCD must exist and round-trip its comment length; a bare
    # "PK\x03\x04" on garbage must not be claimed, so the registry can
    # refuse it as unrecognised instead of corrupt.
    if _find_eocd(data) is None:
        return 0
    return 90


def _dos_date_time_to_mac(date, time_):
    year = ((date >> 9) & 0x7F) + 1980
    month = (date >> 5) & 0x0F
    day = date & 0x1F
    hour = (time_ >> 11) & 0x1F
    minute = (time_ >> 5) & 0x3F
    second = (time_ & 0x1F) * 2
    if not 1 <= month <= 12 or not 1 <= day <= 31:
        return 0
    try:
        stamp = datetime.datetime(year, month, day, hour, minute, second,
                                  tzinfo=datetime.timezone.utc)
    except ValueError:
        return 0
    return int(stamp.timestamp()) + MAC_EPOCH_OFFSET


def _zip64_extra_id(extra, where):
    """Return True when ``extra`` carries a 0x0001 (ZIP64) field."""
    pos = 0
    while pos + 4 <= len(extra):
        extra_id, extra_size = struct.unpack_from("<HH", extra, pos)
        if pos + 4 + extra_size > len(extra):
            raise CorruptError(
                "ZIP: extra field at offset %d in %s runs past the"
                " field" % (pos, where))
        if extra_id == EXTRA_ZIP64:
            return True
        pos += 4 + extra_size
    return False


def _find_eocd(data):
    """Locate the End Of Central Directory record; handles archives
    with a trailing comment."""
    if len(data) < EOCD_SIZE:
        return None
    floor = max(0, len(data) - (EOCD_SIZE + 0xFFFF))
    index = data.rfind(EOCD_SIG, floor)
    while index != -1:
        if len(data) - index < EOCD_SIZE:
            index = data.rfind(EOCD_SIG, floor, index)
            continue
        comment_len = struct.unpack_from("<H", data, index + 20)[0]
        if index + EOCD_SIZE + comment_len == len(data):
            return index
        index = data.rfind(EOCD_SIG, floor, index)
    return None


def _decode_name(raw, flags):
    if flags & FLAG_UTF8:
        return raw.decode("utf-8", errors="replace")
    return raw.decode("cp437")


def _read_central_entries(data, eocd):
    (disk, cd_disk, cd_disk_count, cd_count,
     cd_size, cd_offset, _comment_len) = struct.unpack_from(
        "<HHHHIIH", data, eocd + 4)
    if disk or cd_disk or cd_disk_count != cd_count:
        raise UnsupportedError(
            "ZIP: multi-disk (spanned) ZIP archives are not supported")
    if (cd_count == ZIP64_SENTINEL_16 or cd_size == ZIP64_SENTINEL_32
            or cd_offset == ZIP64_SENTINEL_32):
        raise UnsupportedError("ZIP: ZIP64 archives are not supported yet")
    if cd_offset + cd_size > len(data):
        raise CorruptError(
            "ZIP: central directory at offset %d (%d bytes) runs past end of"
            " file" % (cd_offset, cd_size))
    entries = []
    offset = cd_offset
    end = cd_offset + cd_size
    for number in range(cd_count):
        if offset + 46 > end:
            raise CorruptError(
                "ZIP: central directory record %d at offset %d runs past"
                " the declared end of the directory" % (number, offset))
        if data[offset:offset + 4] != CENTRAL_SIG:
            raise CorruptError(
                "ZIP: central directory record %d at offset %d does not"
                " start with PK\\x01\\x02" % (number, offset))
        (_sig, ver_made, ver_need, flags, method, mtime, mdate, crc,
         comp_size, uncomp_size, name_len, extra_len, comment_len,
         disk_start, _int_attrs, ext_attrs, local_offset) = \
            struct.unpack_from("<IHHHHHHIIIHHHHHII", data, offset)
        if (comp_size == ZIP64_SENTINEL_32 or uncomp_size == ZIP64_SENTINEL_32
                or local_offset == ZIP64_SENTINEL_32
                or disk_start == ZIP64_SENTINEL_16):
            raise UnsupportedError("ZIP: ZIP64 archives are not supported yet")
        name_start = offset + 46
        name_end = name_start + name_len
        extra_end = name_end + extra_len
        record_end = extra_end + comment_len
        if record_end > end:
            raise CorruptError(
                "ZIP: central directory record %d runs past the declared"
                " end of the directory" % number)
        raw_name = data[name_start:name_end]
        extra = data[name_end:extra_end]
        # A 0x0001 (ZIP64) extra field means ZIP64 was needed even if
        # the sentinel values were rewritten; refuse by name.
        if _zip64_extra_id(extra, "central directory record %d" % number):
            raise UnsupportedError("ZIP: ZIP64 archives are not supported yet")
        if disk_start:
            raise UnsupportedError(
                "ZIP: member %r lives on disk %d of a multi-disk archive"
                % (raw_name[:32], disk_start))
        unix_mode = (ext_attrs >> 16) & 0xFFFF
        is_dir = bool(unix_mode and (unix_mode & 0xF000) == 0x4000)
        entries.append({
            "flags": flags,
            "method": method,
            "mtime": mtime,
            "mdate": mdate,
            "crc": crc,
            "comp_size": comp_size,
            "uncomp_size": uncomp_size,
            "name": _decode_name(raw_name, flags),
            "is_dir": is_dir,
            "local_offset": local_offset,
        })
        offset = record_end
    if offset != end:
        # A trailing gap that does not add up to a record means the
        # directory is longer than its records claim; be strict.
        if any(data[offset:end]):
            raise CorruptError(
                "ZIP: %d stray bytes between the central directory records"
                " and its declared end at offset %d" % (end - offset, offset))
    return entries


def _inflate(comp, expected_size, name):
    if expected_size > OUTPUT_CAP:
        raise CorruptError(
            "ZIP: member %r declares %d bytes, more than the 1 GiB"
            " ceiling" % (name, expected_size))
    decompressor = zlib.decompressobj(-15)
    out = decompressor.decompress(comp, OUTPUT_CAP + 1)
    if len(out) > OUTPUT_CAP:
        raise CorruptError(
            "ZIP: member %r exceeds the 1 GiB output ceiling" % name)
    out += decompressor.flush(OUTPUT_CAP + 1 - len(out))
    if len(out) > OUTPUT_CAP:
        raise CorruptError(
            "ZIP: member %r exceeds the 1 GiB output ceiling" % name)
    if not decompressor.eof:
        raise CorruptError(
            "ZIP: member %r deflate stream is truncated" % name)
    if len(out) != expected_size:
        raise CorruptError(
            "ZIP: member %r inflates to %d bytes, not the declared %d"
            % (name, len(out), expected_size))
    if decompressor.unused_data:
        raise CorruptError(
            "ZIP: member %r has %d trailing bytes after the deflate"
            " stream" % (name, len(decompressor.unused_data)))
    return out


def open_data(data, password=None, filename=None):
    # ZIP encryption is refused by name during the member walk, never
    # attempted; the parameter keeps the registry signature.
    if len(data) < EOCD_SIZE:
        raise CorruptError("ZIP: file is too small to be a ZIP archive")
    eocd = _find_eocd(data)
    if eocd is None:
        raise CorruptError("ZIP: no end of central directory found")
    records = _read_central_entries(data, eocd)

    archive = Archive()
    archive.format = "ZIP"
    for record in records:
        name = record["name"]
        flags = record["flags"]
        method = record["method"]
        if flags & FLAG_ENCRYPTED:
            raise PasswordRequiredError(
                "ZIP: member %r is encrypted; this library does not"
                " decrypt ZIP members" % name)
        if flags & FLAG_STRONG_ENCRYPT:
            raise UnsupportedError(
                "ZIP: member %r uses strong encryption, which is not"
                " supported" % name)
        if name.endswith("/") or record["is_dir"]:
            # A directory marker, not a file; the extract path
            # materialises directories from the file entries.
            continue
        local_offset = record["local_offset"]
        if local_offset + 30 > len(data):
            raise CorruptError(
                "ZIP: local header for %r at offset %d runs past end of"
                " file" % (name, local_offset))
        if data[local_offset:local_offset + 4] != LOCAL_SIG:
            raise CorruptError(
                "ZIP: local header for %r at offset %d does not start with"
                " PK\\x03\\x04" % (name, local_offset))
        (_sig, _ver, lflags, lmethod, _mtime, _mdate, _crc,
         _comp, _uncomp, name_len, extra_len) = struct.unpack_from(
            "<IHHHHHIIIHH", data, local_offset)
        header_end = local_offset + 30 + name_len + extra_len
        local_extra = data[local_offset + 30 + name_len:header_end]
        if _zip64_extra_id(local_extra, "the local header for %r" % name):
            raise UnsupportedError("ZIP: ZIP64 archives are not supported yet")
        comp_size = record["comp_size"]
        if header_end + comp_size > len(data):
            raise CorruptError(
                "ZIP: member %r declares %d bytes at offset %d, which runs"
                " past end of file" % (name, comp_size, header_end))
        comp = data[header_end:header_end + comp_size]
        expected = record["uncomp_size"]
        if method == METHOD_STORED:
            out = bytes(comp)
            if len(out) != expected:
                raise CorruptError(
                    "ZIP: stored member %r holds %d bytes, declared %d"
                    % (name, len(out), expected))
        elif method == METHOD_DEFLATE:
            out = _inflate(comp, expected, name)
        else:
            label = _METHOD_NAMES.get(method, "method %d" % method)
            raise UnsupportedError(
                "ZIP: member %r uses compression method %d (%s), which is"
                " not supported yet" % (name, method, label))
        if zlib.crc32(out) != record["crc"]:
            raise CorruptError("ZIP: member %r CRC-32 mismatch" % name)
        stamp = _dos_date_time_to_mac(record["mdate"], record["mtime"])
        entry = Entry(name=name,
                      modified=stamp,
                      created=stamp,
                      data_size=len(out),
                      resource_size=0,
                      _data=out,
                      _rsrc=b"")
        archive.entries.append(entry)
    return archive
