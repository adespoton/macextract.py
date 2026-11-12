"""Arsenic (StuffIt method 15) — the decoder.

Matthew Russotto's write-up is the spec: a byte-stuffing RLE over the
whole file, split into blocks, each block optionally randomised, then a
Burrows-Wheeler transform, move-to-front coding with zero-run
suppression, and a quotient arithmetic coder under nine adaptive
models.  The stream ends with a CRC-32 of the output, coded too.

Two reference implementations agree with every step here: the parent C
project's ``sit_arsenic.c`` and XADMaster's ``XADStuffItArsenicHandle``
+ ``BWT.c``.  Details both hold and this code copies:

* the coder: ``renorm = range // total``, ``frequency = code // renorm``,
  ``code -= renorm * low``, then ``range = range - renorm*low`` when the
  symbol closes the model or ``renorm * freq`` otherwise, renormalising
  while ``range <= HALF`` — integer division, rounding included;
* frequencies start at the increment, grow by it, and halve with
  ``(f + 1) >> 1`` once the total passes the limit;
* the models (first, last, increment, limit): initial 0-1/1/256,
  selector 0-10/8/1024, then 2-3/8, 4-7/4, 8-15/4, 16-31/4, 32-63/2,
  64-127/2, 128-255/1 — all limits 1024.  Selector and MTF models are
  re-initialised after every block; the initial model never is;
* zero counting: selectors 0/1 open a run (state 1, count 1 or 2),
  each further 0 adds the state and each 1 twice it, state doubling,
  terminated by the first selector >= 2 — which is then processed
  normally (10 ends the block after flushing the zeros);
* the RLE state (count/last) resets at every block, but a pending
  repeat does not — which is why the encoder must keep a run's four
  equal bytes and their count byte in one block;
* randomisation flips bit 0 at the cumulative rndtable positions,
  re-seeded per block; the inverse BWT is the counting-sort walk from
  the header's primary index;
* the block size is ``1 << (v + 9)`` with a four-bit ``v``; every real
  stream declares 512 KB, but any size in 512..32 MB is legal and
  blocks may end early (selector 10), so fixtures use small ones.

Output is produced only up to ``length`` — the entry's declared fork
length — and the stream's CRC-32 (when the end marker carried one) is
checked over exactly those bytes.
"""

import zlib

from .errors import CorruptError

NUMBITS = 26
ONE = 1 << (NUMBITS - 1)
HALF = 1 << (NUMBITS - 2)

#: The randomisation table from the spec's Appendix A (256 entries).
RNDTABLE = (
    0xEE, 0x56, 0xF8, 0xC3, 0x9D, 0x9F, 0xAE, 0x2C,
    0xAD, 0xCD, 0x24, 0x9D, 0xA6, 0x101, 0x18, 0xB9,
    0xA1, 0x82, 0x75, 0xE9, 0x9F, 0x55, 0x66, 0x6A,
    0x86, 0x71, 0xDC, 0x84, 0x56, 0x96, 0x56, 0xA1,
    0x84, 0x78, 0xB7, 0x32, 0x6A, 0x3, 0xE3, 0x2,
    0x11, 0x101, 0x8, 0x44, 0x83, 0x100, 0x43, 0xE3,
    0x1C, 0xF0, 0x86, 0x6A, 0x6B, 0xF, 0x3, 0x2D,
    0x86, 0x17, 0x7B, 0x10, 0xF6, 0x80, 0x78, 0x7A,
    0xA1, 0xE1, 0xEF, 0x8C, 0xF6, 0x87, 0x4B, 0xA7,
    0xE2, 0x77, 0xFA, 0xB8, 0x81, 0xEE, 0x77, 0xC0,
    0x9D, 0x29, 0x20, 0x27, 0x71, 0x12, 0xE0, 0x6B,
    0xD1, 0x7C, 0xA, 0x89, 0x7D, 0x87, 0xC4, 0x101,
    0xC1, 0x31, 0xAF, 0x38, 0x3, 0x68, 0x1B, 0x76,
    0x79, 0x3F, 0xDB, 0xC7, 0x1B, 0x36, 0x7B, 0xE2,
    0x63, 0x81, 0xEE, 0xC, 0x63, 0x8B, 0x78, 0x38,
    0x97, 0x9B, 0xD7, 0x8F, 0xDD, 0xF2, 0xA3, 0x77,
    0x8C, 0xC3, 0x39, 0x20, 0xB3, 0x12, 0x11, 0xE,
    0x17, 0x42, 0x80, 0x2C, 0xC4, 0x92, 0x59, 0xC8,
    0xDB, 0x40, 0x76, 0x64, 0xB4, 0x55, 0x1A, 0x9E,
    0xFE, 0x5F, 0x6, 0x3C, 0x41, 0xEF, 0xD4, 0xAA,
    0x98, 0x29, 0xCD, 0x1F, 0x2, 0xA8, 0x87, 0xD2,
    0xA0, 0x93, 0x98, 0xEF, 0xC, 0x43, 0xED, 0x9D,
    0xC2, 0xEB, 0x81, 0xE9, 0x64, 0x23, 0x68, 0x1E,
    0x25, 0x57, 0xDE, 0x9A, 0xCF, 0x7F, 0xE5, 0xBA,
    0x41, 0xEA, 0xEA, 0x36, 0x1A, 0x28, 0x79, 0x20,
    0x5E, 0x18, 0x4E, 0x7C, 0x8E, 0x58, 0x7A, 0xEF,
    0x91, 0x2, 0x93, 0xBB, 0x56, 0xA1, 0x49, 0x1B,
    0x79, 0x92, 0xF3, 0x58, 0x4F, 0x52, 0x9C, 0x2,
    0x77, 0xAF, 0x2A, 0x8F, 0x49, 0xD0, 0x99, 0x4D,
    0x98, 0x101, 0x60, 0x93, 0x100, 0x75, 0x31, 0xCE,
    0x49, 0x20, 0x56, 0x57, 0xE2, 0xF5, 0x26, 0x2B,
    0x8A, 0xBF, 0xDE, 0xD0, 0x83, 0x34, 0xF4, 0x17,
)

#: ``(first, last, increment, limit)`` for the nine models, in the
#: order the references set them up.
MODELS = (
    (0, 1, 1, 256),        # initial: header bits and markers
    (0, 10, 8, 1024),      # selector
    (2, 3, 8, 1024),       # MTF ranks 2-3
    (4, 7, 4, 1024),
    (8, 15, 4, 1024),
    (16, 31, 4, 1024),
    (32, 63, 2, 1024),
    (64, 127, 2, 1024),
    (128, 255, 1, 1024),
)


class Model:
    """One adaptive frequency model: increment, limit, per-symbol
    frequencies, and the total.  ``index`` is the position inside the
    model; the symbol value is ``first + index``."""

    def __init__(self, first, last, increment, limit):
        self.first = first
        self.nsyms = last - first + 1
        self.increment = increment
        self.limit = limit
        self.freq = [increment] * self.nsyms
        self.total = increment * self.nsyms

    def reset(self):
        self.freq = [self.increment] * self.nsyms
        self.total = self.increment * self.nsyms

    def bump(self, index):
        self.freq[index] += self.increment
        self.total += self.increment
        if self.total > self.limit:
            total = 0
            for i, f in enumerate(self.freq):
                f = (f + 1) >> 1
                self.freq[i] = f
                total += f
            self.total = total


class _BitReader:
    """MSB-first bits from the byte string; one byte is fetched only
    when the previous one is spent."""

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.buf = 0
        self.count = 0

    def bit(self):
        if self.count == 0:
            if self.pos >= len(self.data):
                raise CorruptError(
                    "Arsenic: the stream ends inside the arithmetic code")
            self.buf = self.data[self.pos]
            self.pos += 1
            self.count = 8
        self.count -= 1
        return (self.buf >> self.count) & 1


class _Decoder:
    """The quotient arithmetic coder, straight from the spec."""

    def __init__(self, reader):
        self.reader = reader
        self.range = ONE
        self.code = 0
        for _ in range(NUMBITS):
            self.code = (self.code << 1) | reader.bit()

    def symbol(self, model):
        if self.range <= 0 or model.total <= 0 or self.code < 0:
            raise CorruptError("Arsenic: arithmetic coder out of range")
        renorm = self.range // model.total
        if renorm == 0:
            raise CorruptError("Arsenic: arithmetic coder out of range")
        frequency = self.code // renorm
        cum = 0
        index = 0
        last = model.nsyms - 1
        while index < last and cum + model.freq[index] <= frequency:
            cum += model.freq[index]
            index += 1
        size = model.freq[index]
        self.code -= renorm * cum
        if self.code < 0:
            raise CorruptError("Arsenic: arithmetic coder out of range")
        if cum + size == model.total:
            self.range -= renorm * cum
        else:
            self.range = renorm * size
        while self.range <= HALF:
            self.range <<= 1
            self.code = (self.code << 1) | self.reader.bit()
        model.bump(index)
        return model.first + index

    def bits(self, model, count):
        value = 0
        for i in range(count):
            if self.symbol(model):
                value |= 1 << i
        return value


def _mtf_decode(table, rank):
    value = table[rank]
    if rank:
        del table[rank]
        table.insert(0, value)
    return value


def _inverse_bwt(block, primary):
    """The counting-sort inverse: ``transform[k]`` is the row whose
    shifted-left version has rank k, so walking from the primary index
    and reading the block at each step recovers the original order."""
    counts = [0] * 256
    for byte in block:
        counts[byte] += 1
    total = 0
    for c in range(256):
        counts[c], total = total, total + counts[c]
    transform = [0] * len(block)
    for i, byte in enumerate(block):
        transform[counts[byte]] = i
        counts[byte] += 1
    out = bytearray(len(block))
    index = primary
    for i in range(len(block)):
        index = transform[index]
        out[i] = block[index]
    return out


def _read_block(dec, selector, mtfmodels, initial, blocksize):
    """One block: header under the initial model, then selector/rank
    symbols until selector 10, then the models reset and the next
    end-of-file bit (with the CRC-32 when it is 1).  Returns
    ``(block_bytes, primary, randomized, compcrc_or_None)``."""
    table = list(range(256))
    randomized = dec.symbol(initial)
    primary = dec.bits(initial, blocksize.bit_length() - 1)
    block = bytearray()
    while True:
        sel = dec.symbol(selector)
        if sel < 2:
            state = 1
            count = 0
            while sel < 2:
                count += state if sel == 0 else 2 * state
                state *= 2
                sel = dec.symbol(selector)
                if count > blocksize:
                    raise CorruptError(
                        "Arsenic: a zero run past the block size")
            if len(block) + count > blocksize:
                raise CorruptError(
                    "Arsenic: a zero run past the block size")
            block.extend([_mtf_decode(table, 0)] * count)
        if sel == 10:
            break
        if sel == 2:
            rank = 1
        else:
            rank = dec.symbol(mtfmodels[sel - 3])
        if len(block) >= blocksize:
            raise CorruptError("Arsenic: a block past its declared size")
        block.append(_mtf_decode(table, rank))
    if primary >= len(block):
        raise CorruptError("Arsenic: block index past the block")
    selector.reset()
    for model in mtfmodels:
        model.reset()
    compcrc = None
    if dec.symbol(initial):
        lo = dec.bits(initial, 16)
        hi = dec.bits(initial, 16)
        compcrc = lo | (hi << 16)
    return bytes(block), primary, randomized, compcrc


def arsenic_decode(data, length):
    """Decode an Arsenic stream to exactly ``length`` output bytes.

    Raises CorruptError for a stream that is not Arsenic, runs off its
    end, or fails the CRC-32 it carries.
    """
    if length == 0:
        return b""
    reader = _BitReader(data)
    dec = _Decoder(reader)
    initial = Model(*MODELS[0])
    selector = Model(*MODELS[1])
    mtfmodels = [Model(*spec) for spec in MODELS[2:]]
    if dec.bits(initial, 8) != ord("A") or dec.bits(initial, 8) != ord("s"):
        raise CorruptError("Arsenic: bad block header signature")
    blocksize = 1 << (dec.bits(initial, 4) + 9)

    out = bytearray()
    compcrc = None
    eof = dec.symbol(initial)
    while len(out) < length:
        if eof:
            raise CorruptError("Arsenic: the stream ends before the fork does")
        block, primary, randomized, end_crc = _read_block(
            dec, selector, mtfmodels, initial, blocksize)
        if end_crc is not None:
            compcrc = end_crc
        raw = _inverse_bwt(block, primary)
        if randomized:
            rndindex = 0
            rndcount = RNDTABLE[0]
            for i in range(len(raw)):
                if rndcount == i:
                    raw[i] ^= 1
                    rndindex = (rndindex + 1) & 255
                    rndcount += RNDTABLE[rndindex]
        # The byte-stuffing RLE: after four equal bytes the next byte
        # is how many more follow (0 meaning none).  count/last reset
        # per block, as both references do; `repeat` carries over.
        count = 0
        last = 0
        repeat = 0
        i = 0
        # A pending repeat drains before the next block is read, as in
        # the references: `repeat` survives a block, `count`/`last` do
        # not, and neither coexists with a block read.
        while len(out) < length and (i < len(raw) or repeat):
            if repeat:
                repeat -= 1
                out.append(last)
                continue
            byte = raw[i]
            i += 1
            if count == 4:
                count = 0
                if byte == 0:
                    continue
                repeat = byte - 1
                out.append(last)
            elif byte == last:
                count += 1
                out.append(byte)
            else:
                count = 1
                last = byte
                out.append(byte)
        eof = end_crc is not None
    if compcrc is not None and zlib.crc32(bytes(out)) != compcrc:
        raise CorruptError("Arsenic: CRC-32 mismatch")
    return bytes(out)
