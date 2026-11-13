"""LZH/LHA (``.lzh``, ``.lha``) — the LHa member stream.

Layout, from the format's own publication (Masaru Oki's ``header.doc``
of 2 March 1992, shipped with LHa for UNIX, as the parent project
derived it in ``docs/formats/lzh-header.md``), cross-checked against
the published Nifty/LHA Notes pages, Joe Jared's ``lzhformat`` notes,
Wikipedia and the entropymine blog:

  A stream of member headers, each followed by its compressed data.
  The method ID (``-lh5-`` and friends) sits at offset 2 of EVERY
  header level; the level byte sits at offset 20 of every level too.

  Level 0/1 base header::

      0   1   header size MINUS TWO
      1   1   header sum: low byte of the sum of bytes 2..end
      2   5   method ID
      7   4   packed size (level 0) / SKIP SIZE (level 1: also counts
              the extended headers, so each one read shortens the
              stream and moves the data start along)
      11  4   original size
      15  2   MS-DOS time word, then 2 date word (level 0/1);
              4-byte Unix time at level 2/3
      19  1   attribute (MS-DOS attributes; LHa writes 0x20)
      20  1   level (0, 1, 2, 3)
      21  1   name length
      22  n   name (a NUL inside it ends it, as both reference
              readers do)
      22+n 2  file CRC-16/ARC over the DECODED bytes, present iff
              the header is long enough for it (LArc's short headers
              omit it — then no CRC can be checked)
      24+n .. level 1: 1 OS ID then the extended-header chain, whose
             first size word sits INSIDE the header size; level 0:
             an optional extended AREA (for ``U``: a minor version,
             a Unix mtime and a Unix mode)

  Level 2/3 base header::

      0   2   total header size (whole header including the chain's
              zero terminator; the low byte must be nonzero — a
              writer pads one byte when it would be zero)
      2   5   method ID
      7   4   packed size
      11  4   original size
      15  4   Unix modification time
      19  1   attribute
      20  1   level
      21  2   file CRC-16/ARC
      23  1   OS ID
      24  ..  level 3 only: the chain sizes widen to 32-bit and the
              base grows to 28 bytes with the u32 total at 24

  Extended headers: ``[size][type][payload]`` — the size includes its
  own two (four at level 3) bytes, a zero size ends the chain.  This
  reader acts on 0x01 filename, 0x02 dirname (0xff-separated), 0x40
  MS-DOS attributes, 0x50 POSIX mode and 0x54 Unix mtime; the header
  CRC (0x00), the comment (0x3f) and unknown or short ones are stepped
  over.  Level 1 keeps the chain OUTSIDE the header size (the skip
  size pays for it), levels 2 and 3 keep it inside.

  End of archive: a header whose first byte is 0 (everything after it
  must be zero too) or EOF exactly on a member boundary.

The coders this reader implements:

  -lh0-, -lz4-  stored (compressed size must equal original size).
  -lh4- .. -lh7-  LHa v2's "new" algorithm: LZSS over a 4/8/32/64 KiB
        window (12/13/15/16 bits), with three canonical Huffman codes
        rebuilt per block — a 510-symbol command alphabet (256
        literals, then length = 256 + L - 3 for L in 3..256), a
        temporary table that codes the command table's own lengths,
        and an offset table whose symbols are the bit-width of the
        match distance.  Bits are read most-significant-first; a count
        of zero in a table means one symbol that consumes no bits at
        all; the window starts full of SPACES.
  -lhd-         a directory marker: skipped (files carry their own
        full paths, so there is no path stack to keep).

Refused by name: ``-lh1-``, ``-lh2-``, ``-lh3-``, ``-lh8-``,
``-lh9-``, ``-lha-``, ``-lhb-``, ``-lhc-``, ``-lhe-``, ``-lhx-``,
``-lx1-``, ``-lzs-``, ``-lz0-``, ``-lz2-``, ``-lz3-``, ``-lz5-``,
``-lz7-``, ``-lz8-``, ``-pc1-``, ``-pm0-``, ``-pm1-``, ``-pm2-``,
``-pms-``, ``-ah0-``, ``-ari-``, ``-hf0-``, ``-lZ0-``, ``-lZ1-``,
``-lZ5-``, space-wrapped variants and unknown methods; and LHArk's
``-lh7-`` over an algorithm of its own (OS ID ``' '``).

Names decode as mac_roman, split on ``0xff``, ``\\`` and ``/`` and
sanitised through the extract-path sanitiser, so a hostile name cannot
escape an extract directory.  A symlink's ``link|target`` name is kept
whole: classic Mac OS has no symlinks, so it is extracted as the file
the bytes make.

Dates: levels 0/1 store MS-DOS date/time words (the DOS wall clock
treated as UTC, as ARC's reader does); levels 2/3 a Unix time, which
the 0x54 extended header may override.  ``created`` equals
``modified``.

No password support: LHA has no encryption.  A MacLHA archive whose
OS byte is ``'m'`` holds a MacBinary stream; this reader hands back
the stream's bytes as they are (the parent C project unwraps it —
documented here as not done).
"""

import struct

from .._core import MAC_EPOCH_OFFSET, Archive, Entry, _sanitize_name
from .._crc16 import crc16_arc
from ..errors import CorruptError, MacExtractError, UnsupportedError
from .arc import _dos_date_time_to_mac

LZH_MAX_EXT = 64          # extended headers per member, a bound
LZH_MAX_L3 = 1 << 20      # lhasa's LEVEL_3_MAX_HEADER_LEN
LZH_NUM_CODES = 510       # 256 literals + 254 copy lengths (3..256)
LZH_TEMP_BITS = 5
LZH_MAX_TEMP = (1 << LZH_TEMP_BITS) - 1
LZH_MAX_OFFSET = 31
LZH_MAX_LEN_BITS = 31     # a table length's ceiling, as the parent's

# (method -> window bits) for the "new" coder; offbits follows wbits.
_LH_NEW = {
    b"-lh4-": 12,
    b"-lh5-": 13,
    b"-lh6-": 15,
    b"-lh7-": 16,
}
_STORED = (b"-lh0-", b"-lz4-")
_DIR = b"-lhd-"

_REFUSED = frozenset(s.encode() for s in (
    "-lh1-", "-lh2-", "-lh3-", "-lh8-", "-lh9-",
    "-lha-", "-lhb-", "-lhc-", "-lhe-", "-lhx-", "-lx1-",
    "-lzs-", "-lz0-", "-lz2-", "-lz3-", "-lz5-", "-lz7-", "-lz8-",
    "-pc1-", "-pm0-", "-pm1-", "-pm2-", "-pms-",
    "-ah0-", "-ari-", "-hf0-", "-lZ0-", "-lZ1-", "-lZ5-",
))
_IMPLEMENTED = frozenset(_STORED) | frozenset(_LH_NEW) | {_DIR}


# ------------------------------------------------------------------ #
# Small readers                                                       #
# ------------------------------------------------------------------ #


def _u16(data, at, what):
    if at + 2 > len(data):
        raise CorruptError("LZH: %s runs past end of file" % what)
    return struct.unpack_from("<H", data, at)[0]


def _u32(data, at, what):
    if at + 4 > len(data):
        raise CorruptError("LZH: %s runs past end of file" % what)
    return struct.unpack_from("<I", data, at)[0]


class _MsbBits:
    """Most-significant-bit-first bits over one member's data."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def bit(self):
        if self.pos >= len(self.data) * 8:
            raise CorruptError("LZH: compressed data ends early")
        byte = self.data[self.pos >> 3]
        b = (byte >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return b

    def bits(self, n):
        value = 0
        for _ in range(n):
            value = (value << 1) | self.bit()
        return value


def _canon_map(lengths, n):
    """``{(length, code): symbol}`` for canonical MSB-first codes over
    ``lengths[:n]`` (0 = unused), the same arithmetic the fixture
    encoder uses to write them."""
    count = [0] * 33
    maxlen = 0
    for value in lengths[:n]:
        if value > 31:
            raise CorruptError("LZH: table length %d" % value)
        count[value] += 1
        if value > maxlen:
            maxlen = value
    first = [0] * 33
    code = 0
    left = 1
    for length in range(1, maxlen + 1):
        first[length] = code
        code = (code + count[length]) << 1
        left <<= 1
        left -= count[length]
        if left < 0:
            raise CorruptError("LZH: code lengths over-subscribe")
    table = {}
    running = [0] * 33
    for symbol in range(n):
        value = lengths[symbol]
        if value:
            table[(value, first[value] + running[value])] = symbol
            running[value] += 1
    return table, maxlen


def _canon_symbol(table, maxlen, reader):
    code = 0
    for length in range(1, maxlen + 1):
        code = (code << 1) | reader.bit()
        symbol = table.get((length, code))
        if symbol is not None:
            return symbol
    raise CorruptError("LZH: code not in the table")


# ------------------------------------------------------------------ #
# The header                                                          #
# ------------------------------------------------------------------ #


class _Header:
    """One member header, parsed."""

    __slots__ = (
        "level", "method", "compsize", "origsize", "dataoff",
        "crc", "os", "attr", "date", "name_raw", "dir_raw",
        "mode", "dosattr", "mtime",
    )

    def __init__(self):
        self.level = 0
        self.method = b""
        self.compsize = 0
        self.origsize = 0
        self.dataoff = 0
        self.crc = None            # None: a short LArc header, no CRC
        self.os = None             # None: level 0 has no OS byte
        self.attr = 0
        self.date = 0              # Mac-epoch seconds
        self.name_raw = None       # base name field (levels 0/1)
        self.dir_raw = None        # 0x02 extended header
        self.mode = None           # 0x50 / the level-0 'U' area
        self.dosattr = None        # 0x40 extended header
        self.mtime = None          # 0x54 extended header


def _apply_ext(header, kind, payload):
    """One extended header's payload: the five this reader acts on,
    everything else stepped over (lhasa ignores the same returns)."""
    if kind == 0x01:
        if payload:
            header.name_raw = payload
    elif kind == 0x02:
        if payload:
            header.dir_raw = payload
    elif kind == 0x40 and len(payload) >= 2:
        header.dosattr = struct.unpack_from("<H", payload, 0)[0]
    elif kind == 0x50 and len(payload) >= 2:
        header.mode = struct.unpack_from("<H", payload, 0)[0]
    elif kind == 0x54 and len(payload) >= 4:
        value = struct.unpack_from("<I", payload, 0)[0]
        header.mtime = value + MAC_EPOCH_OFFSET


def _read_header(data, pos):
    """Parse the header at ``pos``; raises on anything malformed.

    Method IDs are NOT judged here — a refusal is the caller's
    decision, so the probe can claim a stream whose method it will
    refuse and ``open_data`` can name it.
    """
    avail = len(data) - pos
    if avail < 21:
        raise CorruptError(
            "LZH: only %d bytes of header at offset %d" % (avail, pos))
    level = data[pos + 20]
    if level > 3:
        raise CorruptError(
            "LZH: header level %d at offset %d" % (level, pos))

    header = _Header()
    header.level = level
    header.method = bytes(data[pos + 2:pos + 7])
    header.compsize = _u32(data, pos + 7, "packed size")
    header.origsize = _u32(data, pos + 11, "original size")
    header.attr = data[pos + 19]

    if level in (0, 1):
        hdrsize = data[pos] + 2
        if hdrsize < 22:
            raise CorruptError(
                "LZH: header size %d at offset %d" % (hdrsize, pos))
        if pos + hdrsize > len(data):
            raise CorruptError(
                "LZH: header at offset %d runs past end of file" % pos)
        namelen = data[pos + 21]
        if 22 + namelen > hdrsize:
            raise CorruptError(
                "LZH: name does not fit the header at offset %d" % pos)
        raw = bytes(data[pos + 22:pos + 22 + namelen])
        nul = raw.find(b"\0")
        if nul != -1:               # a NUL inside the name ends it,
            raw = raw[:nul]         # as both reference readers do
        header.name_raw = raw
        if hdrsize >= 24 + namelen:
            header.crc = struct.unpack_from(
                "<H", data, pos + 22 + namelen)[0]
        if sum(data[pos + 2:pos + hdrsize]) & 0xFF != data[pos + 1]:
            raise CorruptError(
                "LZH: header sum mismatch at offset %d" % pos)
        if level == 0:
            # The extended AREA after the CRC: for 'U', a minor
            # version, the Unix mtime and the mode — the mtime
            # overrides the DOS date, as lhasa reads it too.
            if (hdrsize >= 36 + namelen
                    and data[pos + 24 + namelen] == ord("U")):
                unix = struct.unpack_from(
                    "<I", data, pos + 26 + namelen)[0]
                header.mode = struct.unpack_from(
                    "<H", data, pos + 30 + namelen)[0]
                header.date = unix + MAC_EPOCH_OFFSET
            else:
                header.date = _dos_date_time_to_mac(
                    struct.unpack_from("<H", data, pos + 17)[0],
                    struct.unpack_from("<H", data, pos + 15)[0])
            header.dataoff = pos + hdrsize
            return header

        # Level 1: OS byte, then the chain, whose first size word is
        # the last thing inside the header size ("skip size" pays for
        # the elements that follow).
        if hdrsize < 27 + namelen:
            raise CorruptError(
                "LZH: level 1 header at offset %d is too short" % pos)
        header.os = data[pos + 24 + namelen]
        header.date = _dos_date_time_to_mac(
            struct.unpack_from("<H", data, pos + 17)[0],
            struct.unpack_from("<H", data, pos + 15)[0])
        skip = header.compsize        # skip size: elements + stream
        at = pos + hdrsize - 2
        total = 0
        for _ in range(LZH_MAX_EXT + 1):
            size = _u16(data, at, "extended header size")
            if size == 0:
                break
            if size < 3:
                raise CorruptError(
                    "LZH: extended header of %d bytes at offset %d"
                    % (size, at))
            if size > skip - total:
                raise CorruptError(
                    "LZH: extended header at offset %d overruns the"
                    " skip size" % at)
            if at + size > len(data):
                raise CorruptError(
                    "LZH: extended header at offset %d runs past end"
                    " of file" % at)
            _apply_ext(header, data[at + 2],
                       bytes(data[at + 3:at + size]))
            total += size
            at += size
        else:
            raise CorruptError(
                "LZH: more than %d extended headers at offset %d"
                % (LZH_MAX_EXT, pos))
        header.compsize = skip - total
        header.dataoff = pos + hdrsize + total
        return header

    if level == 2:
        if avail < 26:
            raise CorruptError(
                "LZH: only %d bytes of level 2 header at offset %d"
                % (avail, pos))
        hdrsize = struct.unpack_from("<H", data, pos)[0]
        header.os = data[pos + 23]
        # LHA for OS-9/68k 2.01 writes the length of the REST of the
        # header, two bytes short; the OS ID 'K' identifies it.
        if header.os == ord("K"):
            hdrsize += 2
        if hdrsize < 26:
            raise CorruptError(
                "LZH: level 2 header size %d at offset %d"
                % (hdrsize, pos))
        if pos + hdrsize > len(data):
            raise CorruptError(
                "LZH: header at offset %d runs past end of file" % pos)
        header.crc = struct.unpack_from("<H", data, pos + 21)[0]
        header.date = _u32(data, pos + 15, "Unix time")
        if header.date:
            header.date += MAC_EPOCH_OFFSET
        else:
            header.date = 0
        at, width, end = pos + 24, 2, pos + hdrsize
    else:
        if avail < 28:
            raise CorruptError(
                "LZH: only %d bytes of level 3 header at offset %d"
                % (avail, pos))
        if struct.unpack_from("<H", data, pos)[0] != 4:
            raise UnsupportedError(
                "LZH: level 3 header with a word size other than 4")
        hdrsize = struct.unpack_from("<I", data, pos + 24)[0]
        if hdrsize < 28 or hdrsize > LZH_MAX_L3:
            raise CorruptError(
                "LZH: level 3 header size %d at offset %d"
                % (hdrsize, pos))
        if pos + hdrsize > len(data):
            raise CorruptError(
                "LZH: header at offset %d runs past end of file" % pos)
        header.os = data[pos + 23]
        header.crc = struct.unpack_from("<H", data, pos + 21)[0]
        header.date = _u32(data, pos + 15, "Unix time")
        if header.date:
            header.date += MAC_EPOCH_OFFSET
        else:
            header.date = 0
        at, width, end = pos + 28, 4, pos + hdrsize

    # Levels 2 and 3 keep the chain INSIDE the header, so it moves
    # neither the data offset nor the size.
    for _ in range(LZH_MAX_EXT + 1):
        if at + width > end:
            raise CorruptError(
                "LZH: extended header chain at offset %d has no"
                " terminator" % pos)
        size = (_u16(data, at, "extended header size") if width == 2
                else _u32(data, at, "extended header size"))
        if size == 0:
            break
        if size < width + 1 or at + size > end:
            raise CorruptError(
                "LZH: extended header of %d bytes at offset %d"
                % (size, at))
        _apply_ext(header, data[at + width],
                   bytes(data[at + width + 1:at + size]))
        at += size
    else:
        raise CorruptError(
            "LZH: more than %d extended headers at offset %d"
            % (LZH_MAX_EXT, pos))
    header.dataoff = end
    return header


# ------------------------------------------------------------------ #
# Coders                                                              #
# ------------------------------------------------------------------ #


def _read_length(reader):
    """A table length: three bits, and a 7 says a unary tail extends
    it — the ceiling is ours, so a garbage stream cannot spin."""
    length = reader.bits(3)
    if length == 7:
        while reader.bit():
            length += 1
            if length > LZH_MAX_LEN_BITS:
                raise CorruptError("LZH: table length %d" % length)
    return length


def _read_lengths(reader, n, skipafter):
    """``n`` length values, with the temp table's 2-bit skip field
    after its third entry (``skipafter`` 2; the offset table has
    none, -1)."""
    lengths = [0] * n
    i = 0
    while i < n:
        lengths[i] = _read_length(reader)
        if i == skipafter:
            skip = reader.bits(2)
            while skip > 0 and i < n - 1:
                skip -= 1
                i += 1
                lengths[i] = 0
            # C lets a skip run past the count; those lengths are
            # never read, so only the position matters.
            i += skip
        i += 1
    return lengths


def _read_table(reader, width, maxcode, skipafter):
    """The temporary and offset tables: a count in ``width`` bits —
    zero means one symbol that consumes NO bits at all."""
    n = reader.bits(width)
    if n == 0:
        return None, 0, reader.bits(width)
    if n > maxcode:
        n = maxcode
    lengths = _read_lengths(reader, n, skipafter)
    table, maxlen = _canon_map(lengths, n)
    return table, maxlen, None


def _temp_symbol(table, maxlen, single):
    def read(reader):
        if single is not None:
            return single
        return _canon_symbol(table, maxlen, reader)
    return read


def _read_code_table(reader):
    """The 510-symbol command table, its lengths coded through the
    temporary table: 0/1/2 skip a run of unused codes, anything else
    is the length plus two."""
    temp, tmax, tsingle = _read_table(reader, LZH_TEMP_BITS,
                                      LZH_MAX_TEMP, 2)
    read_temp = _temp_symbol(temp, tmax, tsingle)
    n = reader.bits(9)
    if n == 0:
        return None, 0, reader.bits(9)
    if n > LZH_NUM_CODES:
        n = LZH_NUM_CODES
    lengths = [0] * n
    i = 0
    while i < n:
        code = read_temp(reader)
        if code <= 2:
            if code == 0:
                skip = 1
            elif code == 1:
                skip = reader.bits(4) + 3
            else:
                skip = reader.bits(9) + 20
            i += min(skip, n - i)      # the rest are already zero
        else:
            lengths[i] = code - 2
            i += 1
    table, maxlen = _canon_map(lengths, n)
    return table, maxlen, None


def _read_offset(reader, table, maxlen, single, wbits):
    """The distance back to a match: the offset table codes the bit
    WIDTH of the distance, whose top bit is then implicit."""
    if single is not None:
        bits = single
    else:
        bits = _canon_symbol(table, maxlen, reader)
    if bits == 0:
        return 1
    if bits == 1:
        return 2
    if bits > wbits:
        raise CorruptError("LZH: offset width %d for a %d-bit window"
                           % (bits, wbits))
    return reader.bits(bits - 1) + (1 << (bits - 1)) + 1


def _lh_new_decode(comp, origsize, wbits):
    """-lh4- .. -lh7-: LZSS over a space-filled window, one block at a
    time, each with three canonical Huffman codes rebuilt in front of
    its commands."""
    offbits = 4 if wbits < 15 else 5
    wsize = 1 << wbits
    window = bytearray(b" " * wsize)
    mask = wsize - 1
    reader = _MsbBits(comp)
    out = bytearray()
    remaining = 0
    code = code_max = code_single = None
    offset = offset_max = offset_single = None

    while len(out) < origsize:
        if remaining == 0:
            remaining = reader.bits(16)
            code, code_max, code_single = _read_code_table(reader)
            offset, offset_max, offset_single = _read_table(
                reader, offbits, LZH_MAX_OFFSET, -1)
            if remaining == 0:
                continue            # an empty block, tables consumed
        remaining -= 1

        if code_single is not None:
            symbol = code_single
        else:
            symbol = _canon_symbol(code, code_max, reader)

        if symbol < 0x100:
            window[len(out) & mask] = symbol
            out.append(symbol)
            continue

        length = symbol - 0x100 + 3
        dist = _read_offset(reader, offset, offset_max, offset_single,
                            wbits)
        source = len(out) - dist
        for _ in range(length):
            if len(out) >= origsize:
                break               # the tail of an over-long match
            byte = window[source & mask]
            window[len(out) & mask] = byte
            out.append(byte)
            source += 1
    return bytes(out)


# ------------------------------------------------------------------ #
# Names, entries, walk                                                #
# ------------------------------------------------------------------ #


def _split_components(raw):
    """A name's pieces: 0xff between directory components, with a
    backslash or a slash honoured too — the extract sanitiser maps
    them all to '/' anyway."""
    parts = []
    start = 0
    for i in range(len(raw) + 1):
        if i == len(raw) or raw[i] in (0xFF, 0x5C, 0x2F):
            if i > start:
                parts.append(raw[start:i])
            start = i + 1
    return parts


def _entry_name(header):
    components = []
    if header.dir_raw:
        components += _split_components(header.dir_raw)
    if header.name_raw:
        components += _split_components(header.name_raw)
    if not components:
        raise CorruptError("LZH: member has no usable name")
    text = b"/".join(components).decode("mac_roman", errors="replace")
    try:
        return _sanitize_name(text)
    except CorruptError:
        raise CorruptError(
            "LZH: member has no usable name: %r" % text) from None


def _entry_locked(header):
    if header.mode is not None:
        return not (header.mode & 0o200)
    attr = header.attr if header.dosattr is None else header.dosattr
    return bool(attr & 1)


def _plausible_method(data, at):
    """The method ID at ``at + 2``: a dash, three ASCII letters or
    digits, a dash.  Anything alphanumeric is plausible and claimed —
    the reader refuses unknown methods by name, so ``open`` can name
    them rather than report "unrecognised"."""
    if at + 7 > len(data):
        return False
    if data[at + 2] != 0x2D or data[at + 6] != 0x2D:
        return False
    for byte in data[at + 3:at + 6]:
        if not (0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A
                or 0x61 <= byte <= 0x7A):
            return False
    return True


def probe(data):
    """Claim a stream whose method ID sits at offset 2 of a plausible
    header; a broken header is still claimed (50) so ``open`` can
    surface its CorruptError rather than "unrecognised"."""
    if len(data) < 7:
        return 0
    if not _plausible_method(data, 0):
        return 0
    if data[0] == 0:
        return 0
    if len(data) >= 21 and data[20] > 3:
        return 0
    try:
        header = _read_header(data, 0)
    except MacExtractError:
        return 50
    nxt = header.dataoff + header.compsize
    if nxt >= len(data):
        return 60                   # truncated, or EOF on the boundary
    if data[nxt] == 0:
        return 60                   # the end-of-archive marker
    if nxt + 7 > len(data):
        return 60                   # a cut-short next header
    if not _plausible_method(data, nxt):
        return 0
    if nxt + 21 <= len(data) and data[nxt + 20] > 3:
        return 0
    return 60


def open_data(data, password=None, filename=None):
    archive = Archive()
    archive.format = "LHA"
    pos = 0
    while True:
        if pos == len(data):
            break                   # EOF exactly on a member boundary
        if data[pos] == 0:
            # The end-of-archive marker: everything after it is zero.
            for i in range(pos, len(data)):
                if data[i]:
                    raise CorruptError(
                        "LZH: %d bytes of trailing junk after the"
                        " end-of-archive marker at offset %d"
                        % (len(data) - pos, pos))
            break
        header = _read_header(data, pos)
        end = header.dataoff + header.compsize
        if end > len(data):
            raise CorruptError(
                "LZH: member at offset %d declares %d bytes of data,"
                " which runs past end of file" % (pos, header.compsize))

        if header.method == _DIR:
            # A directory marker: skipped.  Files carry their own
            # full paths, so there is no path stack to keep.
            pos = end
            continue
        if header.method not in _IMPLEMENTED:
            raise UnsupportedError(
                "LZH: method %s is not supported yet"
                % header.method.decode("ascii", errors="replace"))
        if header.method == b"-lh7-" and header.os == 0x20:
            # LHArk 0.4d writes -lh7- over an algorithm of its own
            # and marks itself with a space as the OS ID (lhasa calls
            # it -lk7- and decodes it separately).
            raise UnsupportedError(
                "LZH: -lh7- with LHArk's OS byte (' ') is a different"
                " algorithm (lhasa's -lk7-) and is not supported yet")

        name = _entry_name(header)
        comp = bytes(data[header.dataoff:end])
        if header.method in _STORED:
            if header.compsize != header.origsize:
                raise CorruptError(
                    "LZH: stored member %r holds %d bytes, its header"
                    " says %d" % (name, header.compsize,
                                  header.origsize))
            out = comp
        else:
            out = _lh_new_decode(comp, header.origsize,
                                 _LH_NEW[header.method])
        if header.crc is not None and crc16_arc(out) != header.crc:
            raise CorruptError("LZH: CRC-16 mismatch for %r" % name)

        date = header.date if header.mtime is None else header.mtime
        archive.entries.append(Entry(
            name=name,
            created=date,
            modified=date,
            locked=_entry_locked(header),
            data_size=header.origsize,
            resource_size=0,
            _data=out,
            _rsrc=b"",
        ))
        pos = end
    return archive
