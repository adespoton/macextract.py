"""Apple Installer Tome reader — the archive Apple's Installer reads from.

A Tome (file type ``idcp``, creator ``kakc``) is the archive Apple's
Installer reads from, used on System 6 through Mac OS 9 install disks and
by installers built with Apple's Installer SDK.  It holds a flat list of
Mac files, each with a data fork, a resource fork and Finder info.  The
Installer script (a separate file) decides what goes where; a Tome is
only the payload.

The layout as this reader uses it, all integers big-endian:

- 0x00: magic ``6b 63 00 01`` (``kc\\0\\x01``); 0x1a: a u16 record count;
  records of 0x80 bytes each begin at 0x24.  Other header bytes are not
  needed.  (The C reader measured the long at 0x16 to be 0x24 in every
  Tome it holds; this reader uses it only as a probe hint, never as a
  gate — the specification does not define it.)
- Record: +0x06 a Str31 name (Mac Roman; the bytes after the string are
  often uninitialised memory, so only the length byte is read); +0x26
  the four-byte file type; +0x2a the creator; +0x2e and +0x32 the
  creation and modification dates (seconds since 1904); +0x36 Finder
  flags (u16); +0x3c the data fork and +0x4c the resource fork, each a
  set of four u32: the fork's length, the offset of its stream in the
  Tome, the stream's length, and a checksum nobody has identified.  A
  fork whose stream length is zero is absent.  A fork's length may be an
  allocation size larger than its real content, in which case the tail
  is zeros and the stream may stop early (see below).  The per-fork
  checksum is carried nowhere and not checked — nothing public identifies
  it; the one integrity test the format leaves is that a decoded stream
  ends exactly where its record says.
- A fork's stream is a sequence of blocks, one per absolute 64 KiB step
  of output: block k ends when the output reaches (k+1) * 65536 or the
  fork's length, whichever is smaller.  Each block starts on a byte
  boundary with a four-byte header.  Byte 0 = 1 is a stored block: the
  raw bytes follow.  Otherwise byte 1 names the codec: 1 is
  InstaCompOne, 0 is the text codec; any other value is unknown and is
  refused by name.  Bytes 2 and 3 vary; they are ignored.  A compressed
  block runs until the output reaches the block's end; its last copy may
  overshoot into the next block's range (the next block still ends at
  the next fixed multiple of 65536), and the LZ window carries across
  blocks.  Blocks in one fork may be mixed.
- End of stream: decoding stops when the input reaches the fork's
  compressed length.  A token that would read past it is padding and is
  dropped.  Output still short of the fork's length is filled with
  zeros.  A stream whose decoded length does not end exactly where the
  record says fails its entry as CorruptError; a fork's stream reaching
  past the Tome's end fails likewise.

Both codecs are one grammar of MSB-first tokens with a ``mode`` flag
that starts at 1 at the beginning of every block: a copy-length code
``c`` is read; if ``c > 0`` or ``mode == 0`` it is a copy of ``c + 2``
bytes (one more when ``mode == 0``) from a distance read below, and
``mode`` becomes 1; otherwise a literal-count code ``n`` is read and
``n`` literal bytes follow (8 bits each in InstaCompOne, 7 in the text
codec), and ``mode`` becomes 0 when ``n < 63``, else stays 1.  A copy
after a short literal run is therefore one byte longer than the same
``c`` elsewhere.  A distance is one of three forms at level ``s``, the
number of the codec's eleven limits below the output position (absolute,
overshoot included); see the tables below.  The text codec is the same
grammar with 7-bit literals, its own copy-length codes and its own
distance limits, and no 1004 exception.

InstaCompOne's copy-length and literal-count codes are the ones
published in maximumspatium's ResDecompress (InstaCompOne.py, MIT); its
last length code is corrected here as the write-up documents.  The
format itself — the container, the blocks, the end-of-stream rule, the
distance levels and the long-field rule with its 1004 exception — is
from the write-up cited below, which is what the C reader was written
from.  No source of another decoder was transcribed into this module.

Sources: danifunker/rusty-backup issue 109, ``tome-support.zip`` v2
(2026-11-07, MIT), whose ``docs/installer_tome.md`` documents all of the
above; fetched and pinned by sha256 in the C MacExtract project
(``tools/fetch_references.sh``), together with its reader
(``src/fmt_tome.c``, ``src/fmt_tome_probe.c``), consulted for the rules
and corner cases only.  The write-up reports 58 Tomes from the System
7.5 and Mac OS 8/9 install media decoding with every fork's output
exactly its stated length and its stream exactly its stated compressed
length, cross-checked against installed copies of the same files and
against deark.

What this reader does NOT do: the C project additionally reads a
*resource fork* holding 'part' resources as a set of rebuilt resource
suitcases (an iFND per font family, and so on).  That layout is
documented nowhere — it was derived by its author from specimens — so
it is out of scope here; a resource fork is carried through as the
bytes it holds, 'part' resources included, and the suitcase rebuild is
refused by silence rather than by name.  A file that is a bare resource
fork of parts (not a Tome) is not recognised by this module at all.
"""

import struct

from .._core import Archive, Entry
from ..errors import CorruptError, UnsupportedError

TOME_MAGIC = b"\x6b\x63\x00\x01"
HEADER_SIZE = 0x24
RECORD_COUNT_OFF = 0x1a
HEADER_LONG_OFF = 0x16          # measured 0x24 in every Tome seen; probe only
RECORD_SIZE = 0x80
BLOCK = 65536
NAME_OFF = 0x06
TYPE_OFF = 0x26
CREATOR_OFF = 0x2a
CREATED_OFF = 0x2e
MODIFIED_OFF = 0x32
FINDER_FLAGS_OFF = 0x36
DATA_FORK_OFF = 0x3c
RSRC_FORK_OFF = 0x4c
FORK_SIZE = 16

# One prefix code: `width` bits equal to `code`, then `extra` bits added
# to `base`.
_LEN_IC1 = [
    (0x000, 2, 0, 0),    (0x001, 2, 0, 1),    (0x004, 3, 0, 2),
    (0x00A, 4, 0, 3),    (0x00B, 4, 0, 4),    (0x018, 5, 0, 5),
    (0x019, 5, 0, 6),    (0x034, 6, 0, 7),    (0x035, 6, 0, 8),
    (0x036, 6, 0, 9),    (0x037, 6, 0, 10),   (0x00E, 4, 3, 11),
    (0x01E, 5, 3, 19),   (0x03E, 6, 5, 27),   (0x07E, 7, 6, 59),
    (0x0FE, 8, 7, 123),  (0x1FE, 9, 8, 251),  (0x3FE, 10, 9, 507),
    (0x3FF, 10, 10, 1019),
]
_LEN_TXT = [
    (0x000, 3, 0, 0),    (0x001, 3, 0, 1),    (0x002, 3, 0, 2),
    (0x003, 3, 0, 3),    (0x008, 4, 0, 4),    (0x009, 4, 0, 5),
    (0x00A, 4, 0, 6),    (0x00B, 4, 0, 7),    (0x006, 3, 2, 8),
    (0x00E, 4, 3, 12),   (0x01E, 5, 4, 20),   (0x03E, 6, 5, 36),
    (0x07E, 7, 6, 68),   (0x0FE, 8, 7, 132),  (0x1FE, 9, 8, 260),
    (0x3FE, 10, 9, 516), (0x3FF, 10, 10, 1028),
]
_LIT = [
    (0x00, 1, 0, 1),     (0x04, 3, 0, 2),     (0x05, 3, 0, 3),
    (0x06, 3, 2, 4),     (0x0E, 4, 3, 8),     (0x1E, 5, 4, 16),
    (0x1F, 5, 5, 32),
]
_LIM_IC1 = (10, 20, 40, 80, 160, 672, 1000, 2688, 5376, 10752, 21504)
_LIM_TXT = (10, 20, 40, 80, 160, 320, 832, 1280, 2560, 5120, 10240)


def _build_lut(table, width):
    lut = [0xFF] * (1 << width)
    for index, (code, code_width, _extra, _base) in enumerate(table):
        lo = code << (width - code_width)
        span = 1 << (width - code_width)
        for peek in range(lo, lo + span):
            lut[peek] = index
    return lut


_LUT_LEN_IC1 = _build_lut(_LEN_IC1, 10)
_LUT_LEN_TXT = _build_lut(_LEN_TXT, 10)
_LUT_LIT = _build_lut(_LIT, 5)

# The farthest a copy may reach: 5 * 2^11 + 2^15.
_MAX_DISTANCE = 5 * (1 << 11) + (1 << 15)


class _BitReader:
    """MSB-first bits over one fork's stream.

    Bits read past the stream's end are zeros; they are still counted in
    ``bitpos`` (as in the reference reader), so a token straddling the
    end is detected rather than silently satisfied.
    """

    def __init__(self, stream, compressed_length):
        self._stream = stream
        self._clen = compressed_length
        self._bitpos = 0
        self._nbits = 0
        self._bitbuf = 0
        self._fed = 0

    @property
    def bitpos(self):
        return self._bitpos

    @property
    def limit(self):
        return self._clen * 8

    def _need(self, count):
        while self._nbits < count:
            if self._fed < self._clen:
                byte = self._stream[self._fed]
            else:
                byte = 0
            self._bitbuf = (self._bitbuf << 8) | byte
            self._fed += 1
            self._nbits += 8
            self._bitpos = self._fed * 8 - self._nbits

    def bits(self, count):
        if count == 0:
            return 0
        self._need(count)
        shift = self._nbits - count
        value = (self._bitbuf >> shift) & ((1 << count) - 1)
        self._bitbuf &= (1 << shift) - 1
        self._nbits -= count
        self._bitpos = self._fed * 8 - self._nbits
        return value

    def code(self, table, lut, width):
        self._need(width)
        peek = (self._bitbuf >> (self._nbits - width)) & ((1 << width) - 1)
        index = lut[peek]
        if index == 0xFF:
            raise CorruptError("Tome: damaged length code in fork stream")
        _code, code_width, extra, base = table[index]
        shift = self._nbits - code_width
        self._bitbuf &= (1 << shift) - 1
        self._nbits -= code_width
        value = base + self.bits(extra)
        self._bitpos = self._fed * 8 - self._nbits
        return value

    def align_byte(self):
        drop = self._nbits & 7
        if drop:
            self._bitbuf >>= drop
            self._nbits -= drop
            self._bitpos = self._fed * 8 - self._nbits
# --- The two codecs ---------------------------------------------------

def _distance(reader, pos, codec_ic1):
    limits = _LIM_IC1 if codec_ic1 else _LIM_TXT
    level = 0
    while level < 11 and limits[level] < pos:
        level += 1
    if reader.bits(1) == 0:
        return reader.bits(level) + 1
    if reader.bits(1) == 0:
        return reader.bits(level + 2) + (1 << level) + 1
    near = 5 << level
    x = pos - near
    width = 1
    while width < 15 and (1 << width) < x:
        width += 1
    if codec_ic1 and 1004 < x <= 1024:
        width = 11
    return reader.bits(width) + near + 1


def _decode_block(reader, out, codec_ic1, target, stated_length):
    """Decode one compressed block; return True when a token straddled the
    end of the stream and was dropped."""
    length_table = _LEN_IC1 if codec_ic1 else _LEN_TXT
    length_lut = _LUT_LEN_IC1 if codec_ic1 else _LUT_LEN_TXT
    literal_bits = 8 if codec_ic1 else 7
    limit = reader.limit
    pos = len(out)
    mode = 1
    while pos < target and reader.bitpos < limit:
        length = reader.code(length_table, length_lut, 10)
        if length > 0 or mode == 0:
            count = length + 2 + (1 if mode == 0 else 0)
            distance = _distance(reader, pos, codec_ic1)
            if reader.bitpos > limit:
                return True
            if distance > pos:
                raise CorruptError(
                    "Tome: copy distance %d reaches before the start "
                    "of the fork" % distance)
            for _ in range(count):
                out.append(out[pos - distance])
                pos += 1
            mode = 1
        else:
            count = reader.code(_LIT, _LUT_LIT, 5)
            if reader.bitpos + count * literal_bits > limit:
                return True
            if count < 63:
                mode = 0
            else:
                mode = 1
            for _ in range(count):
                out.append(reader.bits(literal_bits))
                pos += 1
    return False


def _decode_fork(stream, fork_length, compressed_length):
    """Decode one fork stream; return ``fork_length`` bytes."""
    reader = _BitReader(stream, compressed_length)
    out = bytearray()
    block_end = 0
    ended = False
    limit = compressed_length * 8
    while len(out) < fork_length and reader.bitpos < limit:
        block_end += BLOCK
        target = min(block_end, fork_length)
        if reader.bitpos + 32 > limit:
            raise CorruptError("Tome: fork stream ends inside a block header")
        byte0 = reader.bits(8)
        codec = reader.bits(8)
        reader.bits(8)              # varies; ignored
        reader.bits(8)              # varies; ignored
        if byte0 == 1:
            if len(out) < target:
                count = target - len(out)
                if reader.bitpos + count * 8 > limit:
                    raise CorruptError(
                        "Tome: stored block runs past the fork's stream")
                for _ in range(count):
                    out.append(reader.bits(8))
            continue
        if codec > 1:
            raise UnsupportedError(
                "Tome: unknown fork codec %d in block header; "
                "only InstaCompOne (1) and the text codec (0) are known"
                % codec)
        ended = _decode_block(reader, out, codec == 1, target, fork_length)
        if ended:
            break
        reader.align_byte()
    if len(out) > fork_length:
        # A last copy may overshoot the end; the output budget stops here.
        del out[fork_length:]
    while len(out) < fork_length:
        out.append(0)
    consumed = compressed_length if ended else reader.bitpos // 8
    if consumed != compressed_length:
        raise CorruptError(
            "Tome: fork stream ends at byte %d of its stated %d"
            % (consumed, compressed_length))
    return bytes(out)


# --- The container ----------------------------------------------------

def _mac_roman(raw):
    try:
        return raw.decode("mac_roman")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _read_fork(data, record, fork_off, label, name):
    length, offset, compressed_length, _checksum = struct.unpack_from(
        ">IIII", record, fork_off)
    if compressed_length == 0:
        return b"", 0
    if offset + compressed_length > len(data):
        raise CorruptError(
            "Tome: the %s fork of %r runs past the end of the file"
            % (label, name))
    stream = data[offset:offset + compressed_length]
    return _decode_fork(stream, length, compressed_length), length


def _parse_record_name(record):
    name_length = record[NAME_OFF]
    if name_length > 31:
        name_length = 31
    return _mac_roman(record[NAME_OFF + 1:NAME_OFF + 1 + name_length])


def open_data(data, password=None, filename=None):
    if len(data) < HEADER_SIZE:
        raise CorruptError("Tome: file is too small for a Tome header")
    if data[:4] != TOME_MAGIC:
        raise CorruptError("Tome: bad magic at byte 0")
    count = struct.unpack_from(">H", data, RECORD_COUNT_OFF)[0]
    if count == 0:
        raise CorruptError("Tome: the record count is zero")
    table_end = HEADER_SIZE + count * RECORD_SIZE
    if table_end > len(data):
        raise CorruptError(
            "Tome: %d records do not fit in this file" % count)

    archive = Archive()
    archive.format = "Apple Installer Tome"
    entries = []
    for index in range(count):
        record = data[HEADER_SIZE + index * RECORD_SIZE:
                      HEADER_SIZE + (index + 1) * RECORD_SIZE]
        name = _parse_record_name(record)
        data_fork, data_length = _read_fork(data, record, DATA_FORK_OFF,
                                            "data", name)
        rsrc_fork, rsrc_length = _read_fork(data, record, RSRC_FORK_OFF,
                                            "resource", name)
        type_code = bytes(record[TYPE_OFF:TYPE_OFF + 4])
        creator = bytes(record[CREATOR_OFF:CREATOR_OFF + 4])
        flags = struct.unpack_from(">H", record, FINDER_FLAGS_OFF)[0]
        entry = Entry(
            name=name,
            type=type_code,
            creator=creator,
            finder_flags=flags,
            created=struct.unpack_from(">I", record, CREATED_OFF)[0],
            modified=struct.unpack_from(">I", record, MODIFIED_OFF)[0],
            finder_info=type_code + creator + struct.pack(">H", flags)
            + b"\0" * 22,
            data_size=data_length,
            resource_size=rsrc_length,
        )
        entry._data = data_fork
        entry._rsrc = rsrc_fork
        entries.append(entry)
    archive.entries = entries
    return archive


def probe(data):
    if len(data) < HEADER_SIZE or data[:4] != TOME_MAGIC:
        return 0
    count = struct.unpack_from(">H", data, RECORD_COUNT_OFF)[0]
    if count == 0:
        return 0
    if HEADER_SIZE + count * RECORD_SIZE > len(data):
        return 0
    if struct.unpack_from(">I", data, HEADER_LONG_OFF)[0] == HEADER_SIZE:
        return 90
    return 60
