"""DiskDoubler — the single compressed file, 'DDAR' and 'DDA2'.

Layout, from the parent project's measured notes
(``docs/formats/diskdoubler-container.md``, ``docs/formats/
diskdoubler-dd.md``, ``docs/formats/diskdoubler-splay-stac.md``) and
its ``src/fmt_dd.c``:

  A compressed file is ``0xABCD0054`` followed by 80 bytes of header
  (or ``0xABCD0030`` and 44 bytes, DiskDoubler ß05 of 1990).  Fields
  past the stated size read as zero.  The 84-byte header is usually
  written twice, the second copy as a trailer inside the entry's
  span.  The header's low word is the header size, so the two magics
  name 48 and 84 bytes.

  'DDAR' (3.x/4.x archiver): a 74-byte header after the magic, then
  124-byte records starting with 'DDAR'.  The archive ends at end of
  file — there is no end marker.  A folder record sets a byte at
  +72; its closing record is a copy of it with the byte at +73 set.
  A file DiskDoubler compressed is creator 'DDAP' and carries an
  84-byte file header at record+124; anything else is stored raw.

  'DDA2' (Pro archiver): a 58-byte header after the magic, then
  variable-length records whose size is stated at +42.  Record type
  at +4: ``0xBBBB`` ends the archive, ``0x8000`` is a folder,
  ``0x1000`` a record whose forks follow raw (no file header, the
  record carrying the metadata and a one-byte XOR of each fork),
  anything else a compressed file header at +56.  A record with a
  negative depth (the u32 at +38 is under 2) is skipped.  An archive
  may end with at most 46 leftover bytes and no end marker.

Compression methods 0..10 per fork, each fork carrying its own:

  0 stored.  1 compress(1) LZW: three leading bytes (the two magic
  bytes and the flags byte) are XORed with 0x5a along with the
  decoded bytes whenever the header garbles the fork — and the fork's
  stored sum has those three bytes added in.  2/5 Jones splay-tree
  codes, one tree per context (256 trees; method 5 takes the count
  from a leading byte, 0 meaning 256).  3 RLE-90.  4 StuffIt's
  serialized Huffman tree.  6/9 AD: a 12-byte block header whose
  bytes XOR to zero, flags bit 0 = an uncompressed block, an MSB-first
  stream with 8-bit literals and matches of 2/3/4/5..20 bytes.
  7 Stac LZS: an 18-byte header, a complemented MSB-first stream, a
  2 KB window, one-byte XOR fork checksum (complemented when the
  fork's length is even).  8 Compact Pro's coder with a 0xfff0 block,
  picked by the sum of 16 leading bytes, checksum CRC-16/ARC.
  10 DDn: LZSS over a 64 KB window, three canonical Huffman codes
  (offsets, literals, lengths) selected by 4-byte heads.

Forks carrying delta distance 1 (the u16 at h+50/h+52, or bit 0x80 of
the method byte) are stored as first differences: ``out[i] =
out[i-1] + s[i]`` mod 256 from zero.  The transform sits OUTSIDE the
checksum, which is taken over the bytes the coder produced.  Anything
but 0 and 1 is refused by name.

Methods 0..5 carry a u16 sum of the decompressed bytes (before the
delta transform), compared against the stored u16 minus any method-1
adjustment; a stored 0 means the sum was not kept.  AD and DDn carry
per-block XORs (each block header's bytes XOR to zero).  Stored XORs
of 0 for AD/DD, so those are checked only by their block headers'
byte checks.
"""

import struct

from .._core import Archive, Entry
from ..errors import CorruptError, UnsupportedError
from .._crc16 import crc16_arc
from .._huffman import decode as _huffman_decode
from .._lzw import lzw_decompress
from .._rle90 import rle90_decode
from .._sit13 import _build as _canon_build
from . import cpt as _cpt

DD_MAGIC = b"\xAB\xCD\x00\x54"
DD_MAGIC48 = b"\xAB\xCD\x00\x30"
DDAR_MAGIC = b"DDAR"
DDA2_MAGIC = b"DDA2"
DDAP = b"DDAP"

MAX_DEPTH = 32


# ------------------------------------------------------------------ #
# probe                                                              #
# ------------------------------------------------------------------ #

def probe(data):
    if len(data) < 8:
        return 0
    magic = data[:4]
    if magic == DD_MAGIC or magic == DD_MAGIC48:
        hsize = 84 if magic == DD_MAGIC else 48
        if len(data) < hsize:
            return 0
        datacomp, rsrccomp = struct.unpack_from(">II", data, 8)
        if magic == DD_MAGIC:
            delta_d, delta_r = struct.unpack_from(">HH", data, 54)
            if delta_d > 1 or delta_r > 1:
                return 0
        if hsize + datacomp + rsrccomp > len(data) + 84:  # trailer allowed
            return 0
        m_data, m_rsrc = data[20], data[21]
        if (m_data & 0x7F) > 10 or (m_rsrc & 0x7F) > 10:
            return 0
        return 85
    if magic == DDAR_MAGIC:
        if len(data) < 78:
            return 0
        if len(data) == 78:
            return 60        # an archive with no records at all
        if data[78:82] != DDAR_MAGIC:
            return 0
        if data[78 + 8] > 63:
            return 0
        return 80
    if magic == DDA2_MAGIC:
        if len(data) < 62:
            return 0
        if len(data) == 62:
            return 60        # ends where the header ends: no records
        if data[62:66] != DDA2_MAGIC:
            return 0
        entrytype = struct.unpack_from(">H", data, 66)[0]
        if entrytype == 0xBBBB:
            return 60
        totalsize = struct.unpack_from(">I", data, 104)[0]
        if totalsize < 46:
            return 0
        return 80
    return 0


# ------------------------------------------------------------------ #
# One fork                                                           #
# ------------------------------------------------------------------ #

class _ForkWriter:
    """Sums and, optionally, the delta transform over decoded bytes.

    ``dist`` is 0 or 1.  The running sum ``out[i] = out[i-1] + s[i]``
    starts from zero and is taken mod 256.  Sums are kept over the
    bytes BEFORE the transform.
    """

    def __init__(self, outlen, dist=0):
        self.outlen = outlen
        self.dist = dist
        self.out = bytearray()
        self.sum = 0
        self.xsum = 0
        self.dbuf = bytearray(256)
        self.dpos = 0

    @property
    def done(self):
        return len(self.out) >= self.outlen

    def byte(self, b):
        if self.done:
            return  # trailing filler is dropped
        self.sum = (self.sum + b) & 0xFFFF
        self.xsum ^= b
        if self.dist:
            b = (b + self.dbuf[(self.dpos - self.dist) & 0xFF]) & 0xFF
            self.dbuf[self.dpos & 0xFF] = b
            self.dpos += 1
        self.out.append(b)


class _MsbBits:
    """MSB-first bits over a slice of the archive, absolute offsets."""

    def __init__(self, data, start, end):
        self.data = data
        self.pos = start * 8
        self.end = end * 8

    def bit(self):
        if self.pos >= self.end:
            raise CorruptError("DiskDoubler: bit stream exhausted")
        byte = self.data[self.pos >> 3]
        value = (byte >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return value

    def bits(self, count):
        value = 0
        for _ in range(count):
            value = (value << 1) | self.bit()
        return value


def _delta_of(method_byte, delta16):
    delta = delta16 or (1 if (method_byte & 0x80) else 0)
    if delta not in (0, 1):
        raise UnsupportedError(
            "DiskDoubler: an unsupported delta distance %d" % delta)
    return delta


def _decode_fork(data, at, complen, outlen, method, delta16, crc, xorval,
                 xorsum, label):
    """Decode one fork to exactly ``outlen`` bytes; verify its check."""
    if outlen == 0:
        return b""
    method_byte = method & 0xFF
    delta = _delta_of(method_byte, delta16)
    m = method_byte & 0x7F
    if m not in range(0, 11):
        raise UnsupportedError(
            "DiskDoubler: %s uses unsupported method %d" % (label, m))
    if m == 8 and delta != 0:
        raise UnsupportedError(
            "DiskDoubler: %s uses method 8 with a delta transform" % label)
    if complen > len(data) - at:
        raise CorruptError(
            "DiskDoubler: %s fork runs past end of file" % label)
    fork = data[at:at + complen]

    if m == 8:
        if complen < 16:
            raise CorruptError("DiskDoubler: %s method-8 stream cut short" % label)
        sub = sum(fork[:16])
        if sub == 0:
            out = _cpt.lzh_decode(fork[16:], outlen, block=0xFFF0)
        else:
            out = _cpt.rle8182_decode(fork[16:], outlen)
        if crc != 0 and crc16_arc(out) != crc:
            raise CorruptError(
                "DiskDoubler: CRC-16/ARC mismatch for %s" % label)
        return out

    writer = _ForkWriter(outlen, delta)
    if m == 0:
        for b in fork:
            writer.byte(b)
        sumadj = 0
    elif m == 1:
        if complen < 3:
            raise CorruptError("DiskDoubler: %s method-1 header cut short" % label)
        m1, m2, flags = fork[0] ^ xorval, fork[1] ^ xorval, fork[2] ^ xorval
        sumadj = (m1 + m2 + flags) & 0xFFFF
        maxbits = flags & 0x1F
        blockmode = bool(flags & 0x80)
        out = lzw_decompress(fork, outlen, maxbits=maxbits,
                             blockmode=blockmode, offset=3, limit=complen - 3)
        for b in out:
            writer.byte(b ^ xorval)
    elif m in (2, 5):
        sumadj = 0
        ntrees = 256
        stream_at = 0
        if m == 5:
            if complen < 1:
                raise CorruptError("DiskDoubler: %s method-5 stream cut short" % label)
            count = fork[0]
            if count == 0:
                count = 256
            if count & (count - 1):
                raise UnsupportedError(
                    "DiskDoubler: %s uses method 5 with a non-power-of-two "
                    "context count %d" % (label, count))
            ntrees = count
            stream_at = 1
        _splay_decode(fork, stream_at, complen - stream_at, writer,
                      xorval, ntrees, label)
    elif m == 3:
        sumadj = 0
        out = rle90_decode(fork, outlen, 0, complen)
        for b in out:
            writer.byte(b)
    elif m == 4:
        sumadj = 0
        out, _ = _huffman_decode(fork, outlen, 0)
        for b in out:
            writer.byte(b)
    elif m in (6, 9):
        sumadj = 0
        _ad_decode(fork, complen, writer, label)
    elif m == 7:
        sumadj = 0
        _stac_decode(fork, complen, writer, label)
    else:  # m == 10
        sumadj = 0
        _ddn_decode(fork, complen, writer, label)

    if not writer.done:
        raise CorruptError(
            "DiskDoubler: %s fork ends before its declared length" % label)

    if xorsum:
        if writer.xsum != (crc & 0xFF):
            raise CorruptError(
                "DiskDoubler: XOR checksum mismatch for %s" % label)
    elif m == 7:
        if crc != 0:
            want = crc & 0xFF
            if (outlen & 1) == 0:
                want ^= 0xFF
            if writer.xsum != want:
                raise CorruptError(
                    "DiskDoubler: XOR checksum mismatch for %s" % label)
    elif m <= 5:
        if crc != 0 and writer.sum != (crc - sumadj) & 0xFFFF:
            raise CorruptError(
                "DiskDoubler: 16-bit sum mismatch for %s" % label)
    return bytes(writer.out)


# ---- methods 2 and 5: splay-tree codes --------------------------- #

class _SplayTree:
    """Jones's splay tree as a complete binary tree over 256 leaves.

    Leaf 256 + b is byte b; node j's children are 2j and 2j + 1; the
    root is 1.  A bit of 0 walks left, 1 walks right, MSB of each
    input byte first.  After every byte its leaf is semi-splayed
    toward the root: each step swaps the node with its grandparent's
    other child.
    """

    def __init__(self):
        self.up = [0] * 512
        self.left = [0] * 256
        self.right = [0] * 256
        for i in range(256):
            self.up[2 * i] = self.up[2 * i + 1] = i
            self.left[i] = 2 * i
            self.right[i] = 2 * i + 1

    def decode(self, bits):
        node = 1
        while node < 256:
            if bits.bit():
                node = self.right[node]
            else:
                node = self.left[node]
        return node

    def splay(self, node):
        while True:
            par = self.up[node]
            if par <= 1:
                return
            grand = self.up[par]
            if self.left[grand] == par:
                other = self.right[grand]
                self.right[grand] = node
            else:
                other = self.left[grand]
                self.left[grand] = node
            if self.left[par] == node:
                self.left[par] = other
            else:
                self.right[par] = other
            self.up[node] = grand
            self.up[other] = par
            node = grand


def _splay_decode(fork, start, size, writer, xorval, ntrees, label):
    trees = [None] * ntrees
    mask = ntrees - 1
    bits = _MsbBits(fork, start, start + size)
    ctx = 0
    while not writer.done:
        tree = trees[ctx]
        if tree is None:
            tree = _SplayTree()
            trees[ctx] = tree
        leaf = tree.decode(bits)
        byte = (leaf - 256) ^ xorval
        writer.byte(byte)
        tree.splay(leaf)
        ctx = (leaf - 256) & mask


# ---- methods 6 and 9: ADn ----------------------------------------- #

AD_BLOCK = 0x2000


def _ad_decode(fork, complen, writer, label):
    pos_in = 0
    win = bytearray(AD_BLOCK)
    while not writer.done:
        if pos_in + 12 > complen:
            raise CorruptError(
                "DiskDoubler: %s block header cut short" % label)
        blockstart = pos_in
        hx = 0
        compsize = uncompsize = 0
        for i in range(2):
            b = fork[pos_in + i]
            compsize = (compsize << 8) | b
            hx ^= b
        for i in range(2, 4):
            b = fork[pos_in + i]
            uncompsize = (uncompsize << 8) | b
            hx ^= b
        if uncompsize > AD_BLOCK:
            raise CorruptError(
                "DiskDoubler: %s block output larger than 0x2000" % label)
        pos_in += 4
        for i in range(4):
            hx ^= fork[pos_in + i]
        pos_in += 4
        hx ^= fork[pos_in]          # data xor
        pos_in += 1
        flags = fork[pos_in]
        hx ^= flags
        pos_in += 1
        hx ^= fork[pos_in]          # byte 10
        pos_in += 1
        if hx != fork[pos_in]:      # byte 11: the XOR of the eleven before
            raise CorruptError(
                "DiskDoubler: %s block header XOR does not check" % label)
        pos_in += 1

        if flags & 1:
            if pos_in + uncompsize > complen:
                raise CorruptError(
                    "DiskDoubler: %s stored block cut short" % label)
            for i in range(uncompsize):
                win[i] = fork[pos_in + i]
            pos_in += uncompsize
            produced = uncompsize
            pos_in = blockstart + 12 + compsize
        else:
            bits = _MsbBits(fork, pos_in, complen)
            produced = 0
            while produced < uncompsize:
                if bits.bit() == 0:
                    win[produced] = bits.bits(8)
                    produced += 1
                    continue
                isfar = bits.bit()
                offset = bits.bits(12 if isfar else 8)
                if offset > produced:
                    raise CorruptError(
                        "DiskDoubler: %s match reaches before the block" % label)
                bit = bits.bit()
                if bit == 0:
                    length = 2
                else:
                    bit = bits.bit()
                    if bit == 0:
                        length = 4 if bits.bit() else 3
                    else:
                        length = bits.bits(4) + 5
                if produced + length > uncompsize:
                    length = uncompsize - produced
                if length > offset:
                    raise CorruptError(
                        "DiskDoubler: %s match longer than its distance" % label)
                for i in range(length):
                    win[produced] = win[produced - offset]
                    produced += 1
            pos_in = blockstart + 12 + compsize

        for i in range(produced):
            writer.byte(win[i])


# ---- method 7: Stac LZS ------------------------------------------- #

STAC_WINDOW = 2048


class _ComplementBits:
    """The Stac fork's bits, every byte complemented, read MSB-first."""

    def __init__(self, data, start, end):
        self.bits = _MsbBits(data, start, end)

    def read(self, count):
        value = self.bits.bits(count)
        return (~value) & ((1 << count) - 1)


def _stac_decode(fork, complen, writer, label):
    if complen < 18:
        raise CorruptError("DiskDoubler: %s Stac header cut short" % label)
    n = int.from_bytes(fork[6:10], "big")
    if n > (complen - 18) // 2:
        raise CorruptError(
            "DiskDoubler: %s Stac chunk table larger than the fork" % label)
    start = 18 + 2 * n
    win = bytearray(STAC_WINDOW)
    pos = 0
    bits = _ComplementBits(fork, start, complen)
    while not writer.done:
        if bits.read(1) == 0:                    # a literal
            k = bits.read(8) ^ 0xFF
            win[pos & (STAC_WINDOW - 1)] = k
            writer.byte(k)
            pos += 1
            continue
        off = bits.read(7 if bits.read(1) else 11)
        if off == 0:
            if not writer.done:
                raise CorruptError(
                    "DiskDoubler: %s Stac stream ends before the fork's "
                    "length" % label)
            return
        length = bits.read(2) + 2
        if length == 5:
            length += bits.read(2)
            if length == 8:
                while True:
                    k = bits.read(4)
                    length += k
                    if k != 15:
                        break
        if off > pos:
            raise CorruptError(
                "DiskDoubler: %s Stac match reaches before the start" % label)
        for _ in range(length):
            k = win[(pos - off) & (STAC_WINDOW - 1)]
            win[pos & (STAC_WINDOW - 1)] = k
            writer.byte(k)
            pos += 1


# ---- method 10: DDn ------------------------------------------------ #

def _ddn_read_code(fork, pos, label):
    """One 4-byte-headed canonical code.  Returns (canon, absolute
    offset of the coded data)."""
    if pos + 4 > len(fork):
        raise CorruptError("DiskDoubler: %s block head cut short" % label)
    head = int.from_bytes(fork[pos:pos + 4], "big")
    numcodes = ((head >> 24) & 0xFF) + 1
    numbytes = (head >> 13) & 0x7FF
    maxlength = (head >> 8) & 0x1F
    numbits = (head >> 3) & 0x1F
    if numbits > 24 or maxlength > 31:
        raise CorruptError("DiskDoubler: %s bad code head" % label)
    end = pos + 4 + numbytes
    if end > len(fork):
        raise CorruptError("DiskDoubler: %s code lengths cut short" % label)
    zero_coded = bool(head & 0x04)
    lengths = []
    bits = _MsbBits(fork, pos + 4, end)
    for _ in range(numcodes):
        if zero_coded and not bits.bit():
            lengths.append(0)
            continue
        value = bits.bits(numbits)
        if value > maxlength:
            raise CorruptError(
                "DiskDoubler: %s code length out of range" % label)
        lengths.append(value)
    return _canon_build(lengths), end


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
    raise CorruptError("DiskDoubler: invalid Huffman code")


def _ddn_window_for(size):
    w = 1024
    while w < size and w < 65536:
        w <<= 1
    return w


def _ddn_decode(fork, complen, writer, label):
    wsize = _ddn_window_for(writer.outlen)
    wmask = wsize - 1
    win = bytearray(wsize)
    wpos = 0
    litcap_ok = 0x10000
    nextblock = 0
    while not writer.done:
        if nextblock + 22 > complen:
            raise CorruptError("DiskDoubler: %s block header cut short" % label)
        base = nextblock
        hx = 0
        uncompsize = numliterals = numoffsets = 0
        lengthcompsize = literalcompsize = offsetcompsize = 0
        p = base
        uncompsize = int.from_bytes(fork[p:p + 4], "big")
        for b in fork[p:p + 4]:
            hx ^= b
        p += 4
        numliterals = int.from_bytes(fork[p:p + 2], "big")
        numoffsets = int.from_bytes(fork[p + 2:p + 4], "big")
        for b in fork[p:p + 4]:
            hx ^= b
        p += 4
        lengthcompsize = int.from_bytes(fork[p:p + 2], "big")
        literalcompsize = int.from_bytes(fork[p + 2:p + 4], "big")
        for b in fork[p:p + 4]:
            hx ^= b
        p += 4
        offsetcompsize = int.from_bytes(fork[p:p + 2], "big")
        hx ^= fork[p] ^ fork[p + 1]
        p += 2
        flags = fork[p]
        hx ^= flags
        p += 1
        for i in range(6):
            hx ^= fork[p + i]
        p += 6
        if hx != fork[p]:
            raise CorruptError(
                "DiskDoubler: %s block header XOR does not check" % label)
        p += 1

        if flags & 0x40:                     # stored block
            if p + uncompsize > complen:
                raise CorruptError(
                    "DiskDoubler: %s stored block cut short" % label)
            for i in range(uncompsize):
                win[wpos & wmask] = fork[p + i]
                wpos += 1
                writer.byte(fork[p + i])
            nextblock = p + uncompsize
            continue

        after = p
        literalstart = after + offsetcompsize
        lengthstart = literalstart + literalcompsize
        nextblock = lengthstart + lengthcompsize
        if nextblock > complen:
            raise CorruptError("DiskDoubler: %s block cut short" % label)
        need = numliterals + numoffsets * 2
        if need > litcap_ok:
            raise CorruptError("DiskDoubler: %s block table too large" % label)

        # offsets
        offs = []
        offcode, code_data = _ddn_read_code(fork, after, label)
        bits = _MsbBits(fork, code_data, after + offsetcompsize)
        for _ in range(numoffsets):
            slot = _canon_decode_msb(offcode, bits)
            if slot < 4:
                offs.append(slot + 1)
                continue
            if slot > 31:
                raise CorruptError("DiskDoubler: %s offset symbol out of range" % label)
            bits_extra = slot // 2 - 1
            start = ((2 + (slot & 1)) << bits_extra) + 1
            offs.append((start + bits.bits(bits_extra)) & 0xFFFF)

        # literals
        lits = []
        if flags & 0x80:
            litcode, code_data = _ddn_read_code(fork, literalstart, label)
            if code_data > literalstart + literalcompsize:
                raise CorruptError("DiskDoubler: %s literal code cut short" % label)
            bits = _MsbBits(fork, code_data, literalstart + literalcompsize)
            for _ in range(numliterals):
                lits.append(_canon_decode_msb(litcode, bits))
        else:
            if literalstart + numliterals > literalstart + literalcompsize:
                raise CorruptError("DiskDoubler: %s literals cut short" % label)
            lits = fork[literalstart:literalstart + numliterals]

        # lengths, and the walk they drive
        lencode, code_data = _ddn_read_code(fork, lengthstart, label)
        if code_data > lengthstart + lengthcompsize:
            raise CorruptError("DiskDoubler: %s length code cut short" % label)
        bits = _MsbBits(fork, code_data, lengthstart + lengthcompsize)

        litpos = offpos = produced = 0
        while produced < uncompsize:
            code = _canon_decode_msb(lencode, bits)
            if code == 0:
                if litpos >= numliterals:
                    raise CorruptError(
                        "DiskDoubler: %s literals exhausted" % label)
                value = lits[litpos]
                litpos += 1
                win[wpos & wmask] = value
                wpos += 1
                writer.byte(value)
                produced += 1
                continue
            if code < 128:
                length = code + 2
                if offpos >= numoffsets:
                    raise CorruptError(
                        "DiskDoubler: %s offsets exhausted" % label)
                offset = offs[offpos]
                offpos += 1
                if offset == 0 or offset > wpos:
                    raise CorruptError(
                        "DiskDoubler: %s match reaches before the fork" % label)
                if produced + length > uncompsize:
                    length = uncompsize - produced
                for _ in range(length):
                    value = win[(wpos - offset) & wmask]
                    win[wpos & wmask] = value
                    wpos += 1
                    writer.byte(value)
                produced += length
                continue
            if code >= 160:
                raise CorruptError("DiskDoubler: %s run length out of range" % label)
            length = 1 << (code - 128)
            if produced + length > uncompsize:
                length = uncompsize - produced
            for _ in range(length):
                if litpos >= numliterals:
                    raise CorruptError(
                        "DiskDoubler: %s literals exhausted" % label)
                value = lits[litpos]
                litpos += 1
                win[wpos & wmask] = value
                wpos += 1
                writer.byte(value)
            produced += length


# ------------------------------------------------------------------ #
# The file header, shared by the three containers                     #
# ------------------------------------------------------------------ #

def _parse_filehdr(hdr):
    """The 80 bytes after the magic (fields past the stated size are
    zero for the 48-byte 1990 variant)."""
    f = {}
    f["datasize"] = int.from_bytes(hdr[0:4], "big")
    f["datacomp"] = int.from_bytes(hdr[4:8], "big")
    f["rsrcsize"] = int.from_bytes(hdr[8:12], "big")
    f["rsrccomp"] = int.from_bytes(hdr[12:16], "big")
    f["datamethod"] = hdr[16]
    f["rsrcmethod"] = hdr[17]
    f["info1"] = hdr[18]
    f["info2"] = hdr[48]
    f["modification"] = int.from_bytes(hdr[20:24], "big")
    f["creation"] = int.from_bytes(hdr[24:28], "big")
    f["type"] = hdr[28:32]
    f["creator"] = hdr[32:36]
    f["finderflags"] = int.from_bytes(hdr[36:38], "big")
    f["datacrc"] = int.from_bytes(hdr[44:46], "big")
    f["rsrccrc"] = int.from_bytes(hdr[46:48], "big")
    f["datadelta"] = int.from_bytes(hdr[50:52], "big")
    f["rsrcdelta"] = int.from_bytes(hdr[52:54], "big")
    f["xorval"] = (0x5A if (f["info1"] >= 0x2A and (f["info2"] & 0x80) == 0)
                   else 0)
    return f


def _finfo_record(ftype, creator, finderflags, location=None):
    info = bytearray(32)
    info[0:4] = ftype
    info[4:8] = creator
    struct.pack_into(">H", info, 8, finderflags)
    if location is not None:
        info[10:14] = location
    return bytes(info)


def _decode_entry_forks(data, start, f, label, xorsum, loc=None):
    """Both forks of one compressed file, in stored order."""
    datacomp, rsrccomp = f["datacomp"], f["rsrccomp"]
    if start + datacomp + rsrccomp > len(data):
        raise CorruptError("DiskDoubler: forks of %s run past end of file" % label)
    dec = _decode_fork(data, start, datacomp, f["datasize"],
                       f["datamethod"], f["datadelta"], f["datacrc"],
                       f["xorval"], xorsum, label + " data fork")
    res = _decode_fork(data, start + datacomp, rsrccomp, f["rsrcsize"],
                       f["rsrcmethod"], f["rsrcdelta"], f["rsrccrc"],
                       f["xorval"], xorsum, label + " resource fork")
    return dec, res


def _mac_roman(raw):
    try:
        return raw.decode("mac_roman")
    except UnicodeDecodeError:
        return raw.decode("mac_roman", errors="replace")


def _make_entry(name, f, data_dec, rsrc_dec, finfo):
    return Entry(
        name=name,
        type=f["type"],
        creator=f["creator"],
        finder_flags=f["finderflags"],
        created=f["creation"],
        modified=f["modification"],
        data_size=f["datasize"],
        resource_size=f["rsrcsize"],
        finder_info=finfo,
        _data=data_dec,
        _rsrc=rsrc_dec,
    )


# ------------------------------------------------------------------ #
# A compressed file                                                  #
# ------------------------------------------------------------------ #

def _host_name(filename):
    if not filename:
        return "diskdoubler"
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if base.lower().endswith(".dd"):
        base = base[:-3]
    return base or "diskdoubler"


def _open_single(data, filename):
    hsize = 84 if data[:4] == DD_MAGIC else 48
    hdr = bytearray(80)
    hdr[:hsize - 4] = data[4:hsize]
    f = _parse_filehdr(bytes(hdr))
    if hsize + f["datacomp"] + f["rsrccomp"] > len(data):
        raise CorruptError("DiskDoubler: forks run past end of file")
    name = _host_name(filename)
    dec, res = _decode_entry_forks(data, hsize, f, name, 0)
    finfo = _finfo_record(f["type"], f["creator"], f["finderflags"]) \
        if hsize == 84 else None
    if finfo is not None:
        info = bytearray(finfo)
        info[10:14] = data[42:46]     # fdLocation, when 3.7 wrote it
        finfo = bytes(info)
    archive = Archive()
    archive.format = "DiskDoubler"
    archive.entries.append(_make_entry(name, f, dec, res, finfo))
    return archive


# ------------------------------------------------------------------ #
# 'DDAR'                                                             #
# ------------------------------------------------------------------ #

def _open_ddar(data):
    archive = Archive()
    archive.format = "DiskDoubler (DDAR)"
    paths = []
    at = 78
    prev = 0
    size = len(data)
    while True:
        if at <= prev:
            raise CorruptError("DiskDoubler: DDAR walk stepped backwards")
        prev = at
        if at == size:
            break                      # the file ends: end of archive
        if at + 124 > size:
            raise CorruptError(
                "DiskDoubler: DDAR record cut short at %d" % at)
        if data[at:at + 4] != DDAR_MAGIC:
            raise CorruptError(
                "DiskDoubler: DDAR record magic not where expected at %d" % at)
        nlen = data[at + 8]
        if nlen > 63:
            nlen = 63
        name = _mac_roman(data[at + 9:at + 9 + nlen])
        isdir = data[at + 72]
        enddir = data[at + 73]
        datasize = int.from_bytes(data[at + 74:at + 78], "big")
        rsrcsize = int.from_bytes(data[at + 78:at + 82], "big")
        created = int.from_bytes(data[at + 82:at + 86], "big")
        modified = int.from_bytes(data[at + 86:at + 90], "big")
        type_ = data[at + 90:at + 94]
        creator = data[at + 94:at + 98]
        finderflags = int.from_bytes(data[at + 98:at + 100], "big")
        location = data[at + 100:at + 104]
        datacrc = int.from_bytes(data[at + 118:at + 120], "big")
        rsrccrc = int.from_bytes(data[at + 120:at + 122], "big")
        start = at + 124
        next_at = start + datasize + rsrcsize
        if next_at > size and not enddir and not isdir:
            raise CorruptError(
                "DiskDoubler: DDAR entry at %d runs past end of file" % at)
        at = next_at

        if enddir:
            if paths:
                paths.pop()
            continue
        if isdir:
            paths.append(name)
            continue
        full = "/".join(paths + [name])

        if (finderflags & 0x20) or creator != DDAP:
            # Stored in the archive: both forks raw.
            f = _parse_filehdr(b"\0" * 80)
            f.update(datasize=datasize, datacomp=datasize,
                     rsrcsize=rsrcsize, rsrccomp=rsrcsize,
                     creation=created, modification=modified,
                     type=type_, creator=creator,
                     finderflags=finderflags,
                     datacrc=datacrc, rsrccrc=rsrccrc,
                     datamethod=0, rsrcmethod=0, xorval=0)
            dec = _decode_fork(data, start, datasize, datasize, 0, 0,
                               datacrc, 0, 0, full + " data fork")
            res = _decode_fork(data, start + datasize, rsrcsize, rsrcsize,
                               0, 0, rsrccrc, 0, 0, full + " resource fork")
            finfo = _finfo_record(type_, creator, finderflags, location)
        else:
            if start + 4 > size or data[start:start + 4] != DD_MAGIC:
                raise CorruptError(
                    "DiskDoubler: DDAR file header magic not where the "
                    "record says at %d" % start)
            if start + 84 > size:
                raise CorruptError(
                    "DiskDoubler: DDAR file header cut short")
            hdr = bytearray(80)
            hdr[:80] = data[start + 4:start + 84]
            f = _parse_filehdr(bytes(hdr))
            inner = 84 + f["datacomp"] + f["rsrccomp"]
            if datasize != inner and datasize != inner + 84:
                raise CorruptError(
                    "DiskDoubler: DDAR record span does not match its "
                    "file header")
            dec, res = _decode_entry_forks(data, start + 84, f, full, 0)
            finfo = _finfo_record(f["type"], f["creator"],
                                  f["finderflags"], location)
        archive.entries.append(_make_entry(full, f, dec, res, finfo))
    return archive


# ------------------------------------------------------------------ #
# 'DDA2'                                                             #
# ------------------------------------------------------------------ #

def _open_dda2(data):
    archive = Archive()
    archive.format = "DiskDoubler Pro (DDA2)"
    paths = []
    at = 62
    prev = 0
    lastlevel = 0
    size = len(data)
    sawend = False
    while True:
        if at <= prev:
            raise CorruptError("DiskDoubler: DDA2 walk stepped backwards")
        prev = at
        if at + 46 > size:
            if 0 <= size - at < 46:
                sawend = True      # marker-less end: at most 46 bytes left
                break
            raise CorruptError(
                "DiskDoubler: DDA2 record runs past end of file")
        if data[at:at + 4] != DDA2_MAGIC:
            break                   # sawend stays False: a cut archive
        start = at
        entrytype = int.from_bytes(data[at + 4:at + 6], "big")
        if entrytype == 0xBBBB:
            sawend = True
            break
        nlen = data[at + 6]
        if nlen > 31:
            nlen = 31
        dirlevel = int.from_bytes(data[at + 38:at + 42], "big") - 2
        totalsize = int.from_bytes(data[at + 42:at + 46], "big")
        if totalsize == 0:
            break                   # sawend stays False
        at = start + totalsize
        if at > size:
            raise CorruptError("DiskDoubler: DDA2 record runs past end of file")
        name = _mac_roman(data[start + 7:start + 7 + nlen])
        if dirlevel < 0:
            continue                # a record that states a depth below the root
        while lastlevel > dirlevel:
            if paths:
                paths.pop()
            lastlevel -= 1
        lastlevel = dirlevel

        if entrytype & 0x8000:      # a folder: deepen the path only
            paths.append(name)
            continue

        full = "/".join(paths + [name])

        if (entrytype & 0xF000) == 0x1000:
            # Stored in the archive with no file header of its own.
            if start + 90 > size:
                raise CorruptError("DiskDoubler: DDA2 raw record cut short")
            f = _parse_filehdr(b"\0" * 80)
            f.update(
                datasize=int.from_bytes(data[start + 78:start + 82], "big"),
                rsrcsize=int.from_bytes(data[start + 82:start + 86], "big"),
                creation=int.from_bytes(data[start + 54:start + 58], "big"),
                modification=int.from_bytes(data[start + 58:start + 62], "big"),
                type=data[start + 62:start + 66],
                creator=data[start + 66:start + 70],
                finderflags=int.from_bytes(data[start + 70:start + 72], "big"),
                datacomp=int.from_bytes(data[start + 78:start + 82], "big"),
                rsrccomp=int.from_bytes(data[start + 82:start + 86], "big"),
                datamethod=0, rsrcmethod=0, xorval=0)
            f["datacomp"] = f["datasize"]
            f["rsrccomp"] = f["rsrcsize"]
            datacrc = data[start + 86]
            forks_at = start + 90
            if forks_at + f["datasize"] + f["rsrcsize"] > size:
                raise CorruptError(
                    "DiskDoubler: DDA2 raw forks run past end of file")
            dec = _decode_fork(data, forks_at, f["datasize"], f["datasize"],
                               0, 0, datacrc, 0, 1, full + " data fork")
            res = _decode_fork(data, forks_at + f["datasize"], f["rsrcsize"],
                               f["rsrcsize"], 0, 0, data[start + 87], 0, 1,
                               full + " resource fork")
            finfo = _finfo_record(f["type"], f["creator"],
                                  f["finderflags"])
        else:
            if start + 140 > size:
                raise CorruptError("DiskDoubler: DDA2 file record cut short")
            if data[start + 56:start + 60] != DD_MAGIC:
                raise CorruptError(
                    "DiskDoubler: DDA2 file header magic not where the "
                    "record says")
            hdr = bytearray(80)
            hdr[:80] = data[start + 60:start + 140]
            f = _parse_filehdr(bytes(hdr))
            forks_at = start + 140
            if forks_at + f["datacomp"] + f["rsrccomp"] > size:
                raise CorruptError(
                    "DiskDoubler: DDA2 forks run past end of file")
            dec, res = _decode_entry_forks(data, forks_at, f, full, 0)
            finfo = _finfo_record(f["type"], f["creator"],
                                  f["finderflags"])
        archive.entries.append(_make_entry(full, f, dec, res, finfo))
    if not sawend:
        raise CorruptError(
            "DiskDoubler: DDA2 archive ends without its end marker")
    return archive


# ------------------------------------------------------------------ #
# Dispatcher                                                         #
# ------------------------------------------------------------------ #

def open_data(data, password=None, filename=None):
    magic = data[:4]
    if magic == DD_MAGIC or magic == DD_MAGIC48:
        return _open_single(data, filename)
    if magic == DDAR_MAGIC:
        return _open_ddar(data)
    if magic == DDA2_MAGIC:
        return _open_dda2(data)
    raise CorruptError("DiskDoubler: not a DiskDoubler archive")
