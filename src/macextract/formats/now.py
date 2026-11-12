"""Now Compress reader — archives and compressed files.

Now Compress has no published description; this reader follows the
measured layout of Now Utilities 5.0.1 (tools/derive_now.py in the C
project): a 24-byte file header, 110-byte member records, a block
table per member and four block coders (stored, LZSS, LZSS under one
Huffman code, and the two-code archive coder).  A compressed file is an
archive of one member.

Each member's data area decodes its resource fork first, then its data
fork.  A member's stream restarts at the boundary between the forks
(an empty record whose end offset repeats the one before it) and at
the head of every member.  A block that starts a stream reaches into a
dictionary cache holding the last 32,768 bytes ending where the
previous stream's FIRST block ended, not into the running window.

Block trailers (the 32-bit sum of the block's own bytes) are not
checked.  The block table and the member records are.
"""

import struct

from .._core import Archive, Entry
from ..errors import CorruptError
from .._sit13 import _build as _canon_build

NOW_ENTRY = 110
NOW_HISTORY = 0x8000
NOW_MAXBLOCKS = 0x2000
NOW_MAXSYMS = 0x122

NOW_LEN_EXTRA = [
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    1,1,2,2,2,2,2,3, 3,3,4,4,4,4,5,5, 5,5
]
NOW_LEN_BASE = [
    0x0000,0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,
    0x0008,0x0009,0x000a,0x000b,0x000c,0x000d,0x000e,0x000f,
    0x0010,0x0012,0x0014,0x0018,0x001c,0x0020,0x0024,0x0028,
    0x0030,0x0038,0x0040,0x0050,0x0060,0x0070,0x0080,0x00a0,
    0x00c0,0x00e0
]
NOW_OFF_EXTRA = [
    0,0,0,0,0,0,0,0, 1,1,1,1,2,2,2,2,
    3,3,3,3,4,4,4,4, 5,5,5,5,8,8,8,8,
    8,8,8,8,9,9,9,9, 10,10,10,10,11,11,11,11,
    12,12,12,12,13,13,13,13
]
NOW_OFF_BASE = [
    0x0000,0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,
    0x0008,0x000a,0x000c,0x000e,0x0010,0x0014,0x0018,0x001c,
    0x0020,0x0028,0x0030,0x0038,0x0040,0x0050,0x0060,0x0070,
    0x0080,0x00a0,0x00c0,0x00e0,0x0100,0x0200,0x0300,0x0400,
    0x0500,0x0600,0x0700,0x0800,0x0900,0x0b00,0x0d00,0x0f00,
    0x1100,0x1500,0x1900,0x1d00,0x2100,0x2900,0x3100,0x3900,
    0x4100,0x5100,0x6100,0x7100,0x8100,0xa100,0xc100,0xe100
]


def _mac_roman(raw):
    try:
        return raw.decode("mac_roman")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


class _NowBits:
    """MSB-first bits over a slice of the archive, relative offsets."""

    def __init__(self, data, start_byte, numbits):
        self.data = data
        self.start = start_byte * 8
        self.pos = start_byte * 8
        self.end = self.pos + numbits

    def offset(self):
        return self.pos - self.start

    def bit(self):
        if self.pos >= self.end:
            raise CorruptError("Now Compress: bit stream exhausted")
        byte = self.data[self.pos >> 3]
        value = (byte >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return value

    def bits(self, count):
        value = 0
        for _ in range(count):
            value = (value << 1) | self.bit()
        return value


def _canon_decode_msb(canon, bits):
    code = 0
    base = 0
    for length in range(1, canon.maxlen + 1):
        code = (code << 1) | bits.bit()
        first = canon.first[length]
        count = canon.count[length]
        if first <= code < first + count:
            return canon.sym[base + code - first]
        base += count
    raise CorruptError("Now Compress: invalid Huffman code")


def _huffman_region(src, nsyms, dstcap, label):
    """Decode one Huffman-coded region: flush byte, four-bit table,
    extra-length count and indices, a pad to even offset, then the
    symbols.  The region says nothing about how many symbols it
    carries, so it is decoded until the bit bound in its header
    instruction bytes runs out."""
    if nsyms > NOW_MAXSYMS:
        raise CorruptError("Now Compress: %d-symbol table is too wide" % nsyms)
    if len(src) < 1:
        raise CorruptError("Now Compress: %s has no header byte" % label)
    flush = src[0]
    if flush > 16:
        raise CorruptError("Now Compress: %s flush byte %d" % (label, flush))

    lengths = [0] * nsyms
    at = 1
    for i in range(nsyms // 2):
        if at >= len(src):
            raise CorruptError("Now Compress: %s table cut short" % label)
        lengths[2 * i] = src[at] >> 4
        lengths[2 * i + 1] = src[at] & 0x0F
        at += 1
    if nsyms & 1:
        lengths[nsyms - 1] = 0

    if at >= len(src):
        raise CorruptError("Now Compress: %s extra-length count missing" % label)
    for _ in range(src[at]):
        at += 1
        if at >= len(src):
            raise CorruptError("Now Compress: %s extra-length table cut short" % label)
        symbol = src[at]
        if symbol >= nsyms:
            raise CorruptError(
                "Now Compress: %s extra-length symbol %d out of range"
                % (label, symbol))
        lengths[symbol] += 16
    at += 1                             # the count byte itself
    if at & 1:
        at += 1                          # the stream starts on an even byte

    numbits = (len(src) - at) * 8
    if flush:
        if numbits < 16 - flush:
            raise CorruptError("Now Compress: %s flush does not fit" % label)
        numbits -= 16 - flush

    canon = _canon_build(lengths)
    bits = _NowBits(src, at, numbits)
    out = bytearray()
    while bits.offset() < numbits:
        if len(out) >= dstcap:
            raise CorruptError("Now Compress: %s decoded too much" % label)
        out.append(_canon_decode_msb(canon, bits))
    return bytes(out)


def _lzss(src, outlen, label):
    """Shape 1: MSB-first flag byte; 1 literal, 0 = match with a
    13-bit offset split over two bytes and a length in the low 3 bits
    of the first (a zero length escapes to a third byte).  The stream
    opens with two unread bytes."""
    out = bytearray()
    at = 2
    if len(src) < 2:
        raise CorruptError("Now Compress: %s stream missing its prefix" % label)
    bits = 0
    numbits = 0
    while at < len(src):
        if numbits == 0:
            bits = src[at]
            at += 1
            numbits = 8
            if at >= len(src):
                raise CorruptError("Now Compress: %s stream cut short" % label)
        if bits & 0x80:
            if len(out) >= outlen:
                raise CorruptError("Now Compress: %s block decoded too much" % label)
            out.append(src[at])
            at += 1
        else:
            if at + 2 > len(src):
                raise CorruptError("Now Compress: %s match cut short" % label)
            b1 = src[at]
            b2 = src[at + 1]
            at += 2
            offset = ((b1 & 0xF8) << 5) | b2
            length = b1 & 0x07
            if length == 0:
                if at >= len(src):
                    raise CorruptError("Now Compress: %s length cut short" % label)
                length = src[at]
                at += 1
            length += 2
            if offset == 0 or offset > len(out):
                raise CorruptError(
                    "Now Compress: %s match reaches before the fork" % label)
            for _ in range(length):
                if len(out) >= outlen:
                    raise CorruptError("Now Compress: %s block decoded too much" % label)
                out.append(out[-offset])
        bits = (bits << 1) & 0xFF
        numbits -= 1
    return bytes(out)


def _newlzss(src, window, outlen):
    """Shape 3: a size u16 (0x2F59 plus the header length), a byte
    nothing reads, an outer flush byte, then a Huffman-coded header
    carrying the two code tables, then the stream.  Matches may reach
    back past the member into what the archive produced before it."""
    if len(src) < 4:
        raise CorruptError("Now Compress: shape-3 block is truncated")
    headersize = (struct.unpack_from(">H", src, 0)[0] - 0x2F59) & 0xFFFF
    at = 4
    if headersize > len(src) - at:
        raise CorruptError("Now Compress: shape-3 header overruns its block")

    tables = _huffman_region(src[at:at + headersize], 20, 0x122 + 0x38,
                             "shape-3 header")
    main_lengths = list(tables[:0x122])
    off_lengths = [(b - 2) if b else 0 for b in tables[0x122:0x122 + 0x38]]
    canon_main = _canon_build(main_lengths)
    canon_off = _canon_build(off_lengths)

    at += headersize
    if at & 1:
        at += 1
    if at > len(src):
        raise CorruptError("Now Compress: shape-3 stream does not fit")

    numbits = (len(src) - at) * 8
    if src[3]:
        if numbits < 16 - src[3]:
            raise CorruptError("Now Compress: shape-3 flush does not fit")
        numbits -= 16 - src[3]

    out = bytearray()
    bits = _NowBits(src, at, numbits)
    while bits.offset() < numbits:
        if len(out) >= outlen:
            raise CorruptError("Now Compress: shape-3 block decoded too much")
        sym = _canon_decode_msb(canon_main, bits)
        if sym < 0x100:
            out.append(sym)
            window.append(sym)
            continue
        sel = sym - 0x100
        if sel >= 0x22:
            raise CorruptError("Now Compress: shape-3 length class %d" % sel)
        length = NOW_LEN_BASE[sel]
        if NOW_LEN_EXTRA[sel]:
            length += bits.bits(NOW_LEN_EXTRA[sel])
        length += 2
        sel = _canon_decode_msb(canon_off, bits)
        if sel >= 0x38:
            raise CorruptError("Now Compress: shape-3 distance class %d" % sel)
        offset = NOW_OFF_BASE[sel]
        if NOW_OFF_EXTRA[sel]:
            offset += bits.bits(NOW_OFF_EXTRA[sel])
        if offset == 0 or offset > len(window):
            raise CorruptError("Now Compress: shape-3 match reaches too far back")
        if len(out) + length > outlen:
            raise CorruptError("Now Compress: shape-3 match overruns its fork")
        for _ in range(length):
            byte = window[-offset]
            out.append(byte)
            window.append(byte)
    return bytes(out)


class _NowState:
    """The dictionary cache shared across streams of one archive."""

    def __init__(self):
        self.dict_cache = bytearray(NOW_HISTORY)


def _sum32(data, at, length):
    total = 0
    for byte in data[at:at + length]:
        total += byte
    return total & 0xFFFFFFFF


def _read_table(data, start, end, label):
    """Read and verify the member's block table.  Returns the list of
    (mode, padding, start, end) blocks in order, skipping empty records
    (which mark stream restarts) and flagging them."""
    if end - start < 4:
        raise CorruptError("Now Compress: %s block table cut short" % label)
    first = struct.unpack_from(">I", data, start)[0]
    nrecs = (first - start - 4) // 8 - 1
    if nrecs < 0 or nrecs > NOW_MAXBLOCKS:
        raise CorruptError("Now Compress: %s block table count %d"
                           % (label, nrecs))
    table_end = first
    if table_end > end:
        raise CorruptError("Now Compress: %s block table ends past its member"
                           % label)
    # The four bytes before the stored sum, then the sum of everything
    # else of the table (the u32 that says where the first block begins
    # counts as stored).
    at = start + 4
    total = struct.unpack_from(">I", data, start)[0]
    for _ in range(nrecs):
        total += _sum32(data, at, 8)
        at += 8
    total += _sum32(data, at, 4)
    if at + 8 > end:
        raise CorruptError("Now Compress: %s block table checksum cut off"
                           % label)
    stored = struct.unpack_from(">I", data, at + 4)[0]
    if total & 0xFFFFFFFF != stored:
        raise CorruptError(
            "Now Compress: %s block table checksum mismatch" % label)
    if table_end != at + 8:
        # first is where the first block begins: the sum sits right there
        raise CorruptError(
            "Now Compress: %s block table does not end where its u32 says"
            % label)

    blocks = []
    last = first
    nextisstart = True
    for i in range(nrecs):
        at = start + 4 + i * 8
        mode = struct.unpack_from(">H", data, at)[0]
        padding = struct.unpack_from(">H", data, at + 2)[0]
        endoff = struct.unpack_from(">I", data, at + 4)[0]
        if endoff == last:
            nextisstart = True      # the boundary between two streams
            continue
        if endoff < last + padding + 4:
            raise CorruptError(
                "Now Compress: %s block %d ends before it starts"
                % (label, i))
        blocks.append((mode, padding, last, endoff, nextisstart))
        last = endoff
        nextisstart = False
    if blocks and last != end:
        raise CorruptError(
            "Now Compress: %s blocks end at %d, the member at %d"
            % (label, last, end))
    return blocks


def _decode_block(block_bytes, mode, window, label):
    """Decode one block.  Shape-3 mutates ``window`` as it goes and the
    caller must not extend it again; the other shapes leave the window
    alone and the caller extends it with the decoded bytes."""
    if mode & 0x20:
        if mode & 0x1F:                       # Huffman, then LZSS
            stream = _huffman_region(block_bytes, 0x100, 0x8000, label)
            return _lzss(stream, 0x8000, label), True
        return _huffman_region(block_bytes, 0x100, 0x8000, label), True
    if mode & 0x40:                            # shape 3
        return _newlzss(block_bytes, window, 0x8000), False
    if mode & 0x1F:                            # LZSS only
        return _lzss(block_bytes, 0x8000, label), True
    return bytes(block_bytes), True             # stored


def _decode_member(data, datastart, dataend, rsrc_size, data_size, label,
                   state):
    """Decode a member's stream into (rsrc, data) bytes."""
    if rsrc_size == 0 and data_size == 0:
        return b"", b""
    blocks = _read_table(data, datastart, dataend, label)
    if not blocks:
        raise CorruptError(
            "Now Compress: %s declares forks but decodes no bytes" % label)

    window = None
    decoded = bytearray()
    for mode, padding, start, end, is_first in blocks:
        bend = end - padding - 4
        block_bytes = data[start:bend]
        if is_first or window is None:
            window = bytearray(state.dict_cache)
        out, caller_extends = _decode_block(block_bytes, mode, window,
                                            "%s, block at %d" % (label, start))
        if caller_extends:
            window.extend(out)
        if is_first:
            state.dict_cache = bytes(window[-NOW_HISTORY:])
        # the window slides: only the last 32 KiB reach the next block
        del window[:-NOW_HISTORY]
        decoded += out

    want = rsrc_size + data_size
    if len(decoded) != want:
        raise CorruptError(
            "Now Compress: %s decoded %d bytes of a fork pair that "
            "declares %d" % (label, len(decoded), want))
    return bytes(decoded[:rsrc_size]), bytes(decoded[rsrc_size:])


def _decode_entry_finder_info(rec):
    return bytes(rec[38:54]) + bytes(rec[66:82])


def open_data(data, password=None, filename=None):
    if len(data) < 134:
        raise CorruptError("Now Compress: file is too small")
    if data[0:2] != b"\0\x02":
        raise CorruptError("Now Compress: not a Now Compress file")
    if data[8] or data[9]:
        raise CorruptError("Now Compress: entry count out of range")
    count = struct.unpack_from(">I", data, 8)[0]
    if count == 0 or count > 0xFFFF:
        raise CorruptError("Now Compress: entry count %d" % count)
    if 24 + count * NOW_ENTRY > len(data):
        raise CorruptError("Now Compress: file cut short in the entry table")

    state = _NowState()
    records = []
    at = 24
    for index in range(count):
        rec = data[at:at + NOW_ENTRY]
        at += NOW_ENTRY
        stored = struct.unpack_from(">I", rec, 106)[0]
        total = 0
        for byte in rec[:106]:
            total += byte
        if total & 0xFFFFFFFF != stored:
            raise CorruptError(
                "Now Compress: entry %d checksum mismatch" % index)
        nlen = rec[0]
        if nlen > 31:
            nlen = 31
        records.append((rec, rec[1:1 + nlen]))

    archive = Archive()
    archive.format = "Now Compress"

    paths = []
    owed = []
    file_records = []
    for index, (rec, name_bytes) in enumerate(records):
        is_dir = bool(struct.unpack_from(">H", rec, 36)[0] & 0x10)
        leaf = _mac_roman(name_bytes)
        # This entry counts against the level it is in; a directory
        # then opens one of its own. Levels close when the count we
        # pushed for them runs out, checked after the current entry is
        # recorded, so a folder the count reached inside is still open
        # for the folder this entry opens.
        if owed:
            owed[-1] -= 1
        file_records.append((rec, tuple(paths), leaf, is_dir))
        if is_dir:
            numdir = struct.unpack_from(">H", rec, 82)[0]
            paths.append(leaf)
            owed.append(numdir)
        while owed and owed[-1] == 0:
            owed.pop()
            paths.pop()

    for index, (rec, parent, leaf, is_dir) in enumerate(file_records):
        if is_dir:
            continue
        name = "/".join(parent + (leaf,))
        datasize = struct.unpack_from(">I", rec, 86)[0]
        rsrcsize = struct.unpack_from(">I", rec, 90)[0]
        datastart = struct.unpack_from(">I", rec, 98)[0]
        dataend = struct.unpack_from(">I", rec, 102)[0]
        if dataend < datastart or dataend > len(data):
            raise CorruptError(
                "Now Compress: entry %r data bounds overrun the file"
                % name)
        label = repr(name)
        rsrc, data_fork = _decode_member(
            data, datastart, dataend, rsrcsize, datasize, label, state)
        entry = Entry(
            name=name,
            type=rec[38:42],
            creator=rec[42:46],
            finder_flags=struct.unpack_from(">H", rec, 46)[0],
            created=struct.unpack_from(">I", rec, 54)[0],
            modified=struct.unpack_from(">I", rec, 58)[0],
            finder_info=_decode_entry_finder_info(rec),
            data_size=datasize,
            resource_size=rsrcsize,
        )
        entry._data = data_fork
        entry._rsrc = rsrc
        archive.entries.append(entry)

    # A compressed file ends with the last member's data area; an
    # archive adds 16 trailer bytes and the format refuses one that
    # lacks them.
    ends = [struct.unpack_from(">I", rec, 102)[0]
            for rec, _, _, is_dir in file_records if not is_dir]
    lastend = max(ends) if ends else 24 + count * NOW_ENTRY
    if len(data) == lastend:
        return archive       # a compressed file
    if len(data) == lastend + 16:
        tail = data[lastend:lastend + 16]
        u32 = struct.unpack_from(">I", tail, 0)[0]
        u16a = struct.unpack_from(">H", tail, 4)[0]
        u16b = struct.unpack_from(">H", tail, 10)[0]
        u32sum = struct.unpack_from(">I", tail, 12)[0]
        total = 0
        for byte in tail[:12]:
            total += byte
        if u32 != lastend or u16a != 1 or u16b != 1 or total != u32sum:
            raise CorruptError("Now Compress: bad archive trailer")
        return archive
    raise CorruptError(
        "Now Compress: file ends %d bytes past the last member"
        % (len(data) - lastend))


def probe(data):
    if len(data) < 134:
        return 0
    if data[0] != 0x00 or data[1] != 0x02:
        return 0
    if data[8] or data[9]:
        return 0
    if data[10] == 0 and data[11] == 0:
        return 0
    nlen = data[24]
    if nlen == 0 or nlen > 31:
        return 0
    for i in range(nlen):
        if data[25 + i] < 32:
            return 0
    total = 0
    for byte in data[24:130]:
        total += byte
    if data[130] or data[131]:
        return 0
    if struct.unpack_from(">H", data, 132)[0] != (total & 0xFFFF):
        return 0
    return 70
