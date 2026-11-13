"""ARC (.arc) — the System Enhancement Associates member stream.

Layout, verified byte for byte against the parent project's own
notes in ``docs/formats/arc-container-and-coders.md`` (derived from
what ARC 5.21q wrote):

  A stream of members. Each opens with ``0x1a`` and a method byte.

  Normal member header (method != 1), 29 bytes::

      0   1   0x1a
      1   1   method
      2   13  name, NUL-padded
      15  4   compressed size, little-endian
      19  2   MS-DOS date
      21  2   MS-DOS time
      23  2   CRC-16/ARC, little-endian, over the DECODED bytes
      25  4   original size, little-endian

  Method 1 ("stored, old") has no original-size field: its
  compressed size IS its original size, so its header is 25 bytes
  and its data begins right after the CRC.

  End of archive: a member header whose method byte is ``0x00`` —
  i.e. a lone ``0x1a 0x00`` — or EOF exactly on a member boundary
  (the marker is optional in the wild).  Trailing junk after the
  marker is an error, as is a cut-short header or member.

The coders this reader implements:

  1, 2  stored.
  3     "packed": RLE-90 and nothing else.  ``0x90`` introduces a run:
        a following ``0x00`` means a literal ``0x90``; any other
        value n means the byte before the ``0x90`` repeats n-1 more
        times.
  4     "squeezed": a little-endian u16 node-pair count, then that
        many pairs of little-endian s16.  A negative value is a leaf
        holding symbol ``-value - 1``; symbol 256 ends the stream.
        A non-negative value is the index of another pair.  Decoding
        starts at pair 0 and reads ONE BIT per step, least-significant
        first; the bit picks which of the two children to follow.
        The symbols are an RLE-90 stream.
  8     "crunched": the member's first byte is the maximum code width
        (12 in what the encoder writes); after it, LZW read
        least-significant-bit first — codes start at 9 bits, widen as
        the dictionary fills, 256 clears the table, the first code
        assigned is 257.  The output is an RLE-90 stream.
  9     "squashed": the same LZW to 13 bits, alone — no width byte,
        no RLE-90.

The garble: ARC's ``g<password>`` XORs the (upper-cased) password
over each member's COMPRESSED bytes, by position from the first
byte again at every member, and leaves the header alone.  Nothing in
the file says it was done, so the member's CRC-16 is the only
evidence: when a password is given, each member is decoded with the
password XOR applied and graded by CRC; a mismatch (or a coder that
rejects the stream) raises ``BadPasswordError`` and no entry is
returned.  When no password is given, a plain decode that fails CRC
raises ``CorruptError``.

Refused by name: methods 5, 6 and 7 ("crunched", the hashed-table
LZW), 0x0a (PAK "crushed", also ARC 7's "Trimmed"), 0x0b (PAK
"distilled"), 0x7f (Unix compress), and the ARC 7.x container —
its informational items (methods 20, 21 and 22) and its subdirectory
items (methods 30 and 31).  An ArcMac file (``0x1b`` where an ARC
member header belongs) is refused by name too.

ARC has no folders: entries are flat files.  A member name carrying
a path separator or a ``..`` component is sanitised before it is
stored in the entry (the extract path applies the same sanitiser),
so a hostile name cannot escape an extract directory.

Dates: the member's date/time are MS-DOS words (bits 15-9 years
since 1980 in date; bits 15-11 hours, 10-5 minutes, 4-0 seconds/2 in
time), local time with no zone.  They are stored in the entry as
Mac-epoch seconds, the DOS wall clock treated as UTC.
"""

import struct
from datetime import datetime, timezone

from .._core import MAC_EPOCH_OFFSET, Archive, Entry, _sanitize_name
from .._crc16 import crc16_arc
from .._lzw import LsbBitReader, lzw_decompress, lzw_decompress_all
from .._rle90 import rle90_decode
from ..errors import BadPasswordError, CorruptError, UnsupportedError

ARC_NAME_LEN = 13
HDR_OLD = 0x19          # method 1: ... crc at 23, data at 25
HDR = 0x1D              # other methods: data at 29

METHOD_OLD_STORED = 0x01
METHOD_STORED = 0x02
METHOD_PACKED = 0x03
METHOD_SQUEEZED = 0x04
METHOD_CRUNCH5 = 0x05
METHOD_CRUNCH6 = 0x06
METHOD_CRUNCH7 = 0x07
METHOD_CRUNCH8 = 0x08
METHOD_SQUASHED = 0x09
METHOD_CRUSHED = 0x0A
METHOD_DISTILLED = 0x0B
METHOD_INFO = 0x14
METHOD_FILEINFO = 0x15
METHOD_OSINFO = 0x16
METHOD_DIR = 0x1E
METHOD_DIREND = 0x1F
METHOD_COMPRESSED = 0x7F

# Informational items (ARC 7.x).  Their name field is empty.
_ARC7_ITEMS = (METHOD_INFO, METHOD_FILEINFO, METHOD_OSINFO)
# Subdirectory items (ARC 7.x).
_ARC7_DIR_ITEMS = (METHOD_DIR, METHOD_DIREND)

_REFUSED = {
    METHOD_CRUNCH5: "method 5 (crunched)",
    METHOD_CRUNCH6: "method 6 (crunched)",
    METHOD_CRUNCH7: "method 7 (crunched)",
    METHOD_CRUSHED: "method 0x0a (crushed, or ARC 7's Trimmed)",
    METHOD_DISTILLED: "method 0x0b (distilled)",
    METHOD_COMPRESSED: "method 0x7f (compress)",
}

_MAX_PAIRS = 257          # the format's ceiling; 514 s16 values


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #


def _u16(data, at):
    if at + 2 > len(data):
        raise CorruptError("ARC: header cut short")
    return struct.unpack_from("<H", data, at)[0]


def _u32(data, at):
    if at + 4 > len(data):
        raise CorruptError("ARC: header cut short")
    return struct.unpack_from("<I", data, at)[0]


def _s16(data, at):
    return struct.unpack_from("<h", data, at)[0]


def _upper_password(password):
    """The garble upper-cases the password before XORing with it."""
    if password is None:
        return None
    if isinstance(password, str):
        password = password.encode("latin-1", errors="replace")
    else:
        password = bytes(password)
    return bytes(b - 32 if 97 <= b <= 122 else b for b in password)


def _garble(data, password):
    """XOR the (upper-cased) password over a member's compressed bytes,
    position resetting to the password's first byte for every member."""
    if not password:
        return bytes(data)
    length = len(password)
    return bytes(b ^ password[i % length] for i, b in enumerate(data))


def _dos_date_time_to_mac(date, time_):
    year = ((date >> 9) & 0x7F) + 1980
    month = (date >> 5) & 0x0F
    day = date & 0x1F
    hour = (time_ >> 11) & 0x1F
    minute = (time_ >> 5) & 0x3F
    second = (time_ & 0x1F) * 2
    if not 1 <= month <= 12:
        return 0
    try:
        stamp = datetime(year, month, day, hour, minute, second,
                         tzinfo=timezone.utc)
    except ValueError:
        return 0
    return int(stamp.timestamp()) + MAC_EPOCH_OFFSET


def _member_name(raw):
    """Decode the 13-byte name field the way the format's own
    reader trims it (one trailing space, then one trailing dot),
    then make it safe as a relative path."""
    end = raw.find(b"\0")
    if end != -1:
        raw = raw[:end]
    if len(raw) > 1 and raw.endswith(b" "):
        raw = raw[:-1]
    if len(raw) > 1 and raw.endswith(b"."):
        raw = raw[:-1]
    try:
        name = raw.decode("mac_roman")
    except UnicodeDecodeError:
        name = raw.decode("mac_roman", errors="replace")
    if ("/" in name or "\\" in name or ":" in name or ".." in name
            or name in ("", ".")):
        # Hostile or odd member name: normalise through the same
        # sanitiser the extract path uses.  Raises CorruptError when
        # nothing usable remains.
        name = _sanitize_name(name)
    if not name:
        raise CorruptError("ARC: member has no usable name")
    return name


def _name_ok(raw):
    """The probe's name check: first byte non-zero, no control bytes."""
    if raw[0] == 0:
        return False
    for byte in raw:
        if byte == 0:
            break
        if byte < 32:
            return False
    return True


# ------------------------------------------------------------------ #
# Coders                                                              #
# ------------------------------------------------------------------ #


def _squeeze_decode(comp):
    """Method 4, up to the RLE-90 stage: a Huffman walk over the
    stored node pairs, one bit per step, LSB-first."""
    if len(comp) < 2:
        raise CorruptError("ARC: squeezed member is too short")
    count = struct.unpack_from("<H", comp, 0)[0]
    numnodes = count * 2
    if count < 1 or numnodes >= 2 * _MAX_PAIRS:
        raise CorruptError("ARC: squeezed member carries %d node pairs"
                           % count)
    pos = 2
    if len(comp) < 2 + numnodes * 2:
        raise CorruptError("ARC: squeezed member's tree runs past its data")
    nodes = [_s16(comp, pos + 2 * i) for i in range(numnodes)]
    reader = LsbBitReader(comp, offset=2 + numnodes * 2,
                          limit=len(comp) - (2 + numnodes * 2))
    out = bytearray()
    depth = 0
    node = 0
    while True:
        bit = reader.read_code(1)
        if bit is None:
            break                       # input ran out; the CRC grades it
        index = 2 * node + bit
        if index >= numnodes:
            raise CorruptError("ARC: squeezed member's tree walks off the end")
        value = nodes[index]
        if value < 0:
            symbol = -value - 1
            if symbol == 256:
                return bytes(out)
            if symbol > 255:
                raise CorruptError("ARC: squeezed member symbol %d" % symbol)
            out.append(symbol)
            node = 0
            depth = 0
            continue
        node = value
        depth += 1
        if depth > 64:
            raise CorruptError("ARC: squeezed member's tree is cyclic")
    return bytes(out)


def _decode_member(method, comp, original_size, name):
    """Decode one member's compressed bytes to ``original_size`` bytes."""
    if method in (METHOD_OLD_STORED, METHOD_STORED):
        out = bytes(comp)
        if len(out) != original_size:
            raise CorruptError(
                "ARC: stored member %r holds %d bytes, its header says %d"
                % (name, len(out), original_size))
        return out
    if method == METHOD_PACKED:
        return rle90_decode(comp, original_size)
    if method == METHOD_SQUEEZED:
        return rle90_decode(_squeeze_decode(comp), original_size)
    if method == METHOD_CRUNCH8:
        if not comp:
            raise CorruptError("ARC: crunched member %r is empty" % name)
        width = comp[0]
        if width != 0x0C:
            raise CorruptError(
                "ARC: crunched member %r opens with code width %d, not 12"
                % (name, width))
        raw = lzw_decompress_all(comp, maxbits=width, blockmode=True,
                                 offset=1, limit=len(comp) - 1)
        return rle90_decode(raw, original_size)
    if method == METHOD_SQUASHED:
        return lzw_decompress(comp, original_size, maxbits=13,
                              blockmode=True, offset=0, limit=len(comp))
    raise CorruptError("ARC: member %r uses method %d" % (name, method))


# ------------------------------------------------------------------ #
# Container                                                           #
# ------------------------------------------------------------------ #


def _is_arcmac(data):
    """An ArcMac file: a Macintosh header, with the PC ARC header
    59 bytes in (``0x1b ... 0x1a``)."""
    return (len(data) >= 61 and data[0] == 0x1B and data[59] == 0x1A
            and data[1] != 0x00 and data[1] == data[60])


def probe(data):
    if len(data) < HDR_OLD:
        return 0
    if _is_arcmac(data):
        return 50
    if data[0] != 0x1A:
        return 0
    method = data[1]
    if method == 0:
        return 0
    if method in _ARC7_ITEMS:
        pass                        # informational items carry no name
    elif method in _ARC7_DIR_ITEMS or method in _REFUSED or (
            method in (METHOD_OLD_STORED, METHOD_STORED, METHOD_PACKED,
                       METHOD_SQUEEZED, METHOD_CRUNCH8, METHOD_SQUASHED)):
        if not _name_ok(data[2:2 + ARC_NAME_LEN]):
            return 0
    else:
        return 0
    header = HDR_OLD if method == METHOD_OLD_STORED else HDR
    if len(data) < header:
        return 0
    compsize = _u32(data, 0x0F)
    uncompsize = compsize if method == METHOD_OLD_STORED else _u32(data, 0x19)
    if uncompsize > 0x7FFFFFFF:
        return 0
    next_at = header + compsize
    if next_at > len(data):
        # A truncated archive: claim it so the parser can refuse it as
        # corrupt rather than as unrecognised.
        return 60
    if next_at == len(data):
        return 60                   # lone member, file ends on the boundary
    if data[next_at] == 0x1A:
        return 60                   # the next member starts where it should
    return 0


def open_data(data, password=None, filename=None):
    if _is_arcmac(data):
        raise UnsupportedError(
            "ArcMac: ArcMac archives (0x1b magic before the ARC header)"
            " are not supported yet")
    if len(data) < 2 or data[0] != 0x1A:
        raise CorruptError("ARC: not an ARC archive")

    garble = _upper_password(password)
    archive = Archive()
    archive.format = "ARC"

    pos = 0
    while True:
        if pos == len(data):
            break                   # EOF exactly on a member boundary
        if pos + 2 > len(data):
            raise CorruptError(
                "ARC: file ends %d bytes into a member header at offset %d"
                % (len(data) - pos, pos))
        if data[pos] != 0x1A:
            raise CorruptError(
                "ARC: byte 0x%02x at offset %d where a member header"
                " (0x1a) was expected" % (data[pos], pos))
        method = data[pos + 1]
        if method == 0x00:
            if pos + 2 != len(data):
                raise CorruptError(
                    "ARC: %d bytes of trailing junk after the"
                    " end-of-archive marker at offset %d"
                    % (len(data) - pos - 2, pos))
            break

        if method in _ARC7_ITEMS:
            raise UnsupportedError(
                "ARC: method %d (an ARC 7.x informational item) is not"
                " supported yet" % method)
        if method in _ARC7_DIR_ITEMS:
            raise UnsupportedError(
                "ARC: method %d (an ARC 7.x subdirectory item) is not"
                " supported yet" % method)
        if method in _REFUSED:
            raise UnsupportedError(
                "ARC: %s is not supported yet" % _REFUSED[method])

        if method == METHOD_OLD_STORED:
            header, original_size = HDR_OLD, None
        elif method in (METHOD_STORED, METHOD_PACKED, METHOD_SQUEEZED,
                        METHOD_CRUNCH8, METHOD_SQUASHED):
            header = HDR
        else:
            raise CorruptError(
                "ARC: method %d at offset %d is not one this reader"
                " knows" % (method, pos))

        if pos + header > len(data):
            raise CorruptError(
                "ARC: member header at offset %d runs past end of file"
                % pos)
        compsize = _u32(data, pos + 0x0F)
        date = _u16(data, pos + 0x13)
        time_ = _u16(data, pos + 0x15)
        crc16 = _u16(data, pos + 0x17)
        original_size = compsize if method == METHOD_OLD_STORED \
            else _u32(data, pos + 0x19)
        name = _member_name(data[pos + 2:pos + 2 + ARC_NAME_LEN])

        member_end = pos + header + compsize
        if member_end > len(data):
            raise CorruptError(
                "ARC: member %r at offset %d declares %d bytes of data,"
                " which runs past end of file" % (name, pos, compsize))
        comp = data[pos + header:member_end]
        if garble:
            comp = _garble(comp, garble)

        try:
            out = _decode_member(method, comp, original_size, name)
        except CorruptError as error:
            if password is not None:
                raise BadPasswordError(
                    "ARC: incorrect password for %r (%s)" % (name, error)
                ) from error
            raise

        if crc16_arc(out) != crc16:
            if password is not None:
                raise BadPasswordError(
                    "ARC: incorrect password for %r (CRC-16 mismatch)"
                    % name)
            raise CorruptError("ARC: CRC-16 mismatch for %r" % name)

        stamp = _dos_date_time_to_mac(date, time_)
        archive.entries.append(Entry(
            name=name,
            created=stamp,
            modified=stamp,
            data_size=original_size,
            resource_size=0,
            _data=out,
            _rsrc=b"",
        ))
        pos = member_end
    return archive
