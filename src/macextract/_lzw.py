"""Unix compress(1)-compatible LZW decoder, block mode.

Codes are LSB-first bit strings of 9..maxbits bits. A 256 clear code
resets the table and the width to 9 and discards the rest of the
eight-code group in force. The width widens by one at each power of two
the table reaches. A code may name the entry it is itself about to
define.

Used by AppleLink packages (13 bits, block mode), MacBinary-adjacent
.Z files, ARC methods 8/9 and DiskDoubler method 1. Written from the
published algorithm and the format notes; no code was copied.
"""

from .errors import CorruptError


class LsbBitReader:
    def __init__(self, data, offset=0, limit=None):
        self.data = data
        self.pos = offset
        self.limit = len(data) if limit is None else offset + limit
        self.bitbuf = 0
        self.nbits = 0

    def read_code(self, size):
        while self.nbits < size:
            if self.pos >= self.limit:
                return None
            self.bitbuf |= self.data[self.pos] << self.nbits
            self.pos += 1
            self.nbits += 8
        value = self.bitbuf & ((1 << size) - 1)
        self.bitbuf >>= size
        self.nbits -= size
        return value


def lzw_decompress(data, out_len, maxbits=13, blockmode=True, offset=0,
                   limit=None):
    """Decode exactly ``out_len`` bytes; returns them. Raises
    CorruptError on truncation or a code that names no defined entry.
    """
    if out_len < 0:
        raise CorruptError("LZW: output length must not be negative")
    if out_len == 0:
        return b""
    if maxbits < 9 or maxbits > 16:
        raise CorruptError("LZW: maxbits must be between 9 and 16")

    maxsymbols = 1 << maxbits
    clear = 256
    bump = 1 if blockmode else 0
    numsymbols = 256 + bump
    symbolsize = 9
    symbolcounter = 0
    prevsymbol = -1
    parent = [0] * maxsymbols
    chr_ = list(range(256)) + [0] * (maxsymbols - 256)
    len_ = [1] * 256 + [0] * (maxsymbols - 256)

    reader = LsbBitReader(data, offset, limit)
    out = bytearray()

    def string_of(sym):
        parts = bytearray()
        node = sym
        for _ in range(len_[sym]):
            parts.append(chr_[node])
            node = parent[node]
        return parts[::-1]

    while len(out) < out_len:
        code = reader.read_code(symbolsize)
        if code is None:
            raise CorruptError("LZW: bit stream exhausted")
        symbolcounter += 1
        if blockmode and code == clear:
            remainder = symbolcounter % 8
            if remainder:
                left = (8 - remainder) * symbolsize
                while left > 0:
                    chunk = 16 if left > 16 else left
                    if reader.read_code(chunk) is None:
                        raise CorruptError("LZW: bit stream exhausted in clear skip")
                    left -= chunk
            numsymbols = 256 + bump
            prevsymbol = -1
            symbolsize = 9
            symbolcounter = 0
            continue
        if code < numsymbols:
            string = string_of(code)
        elif code == numsymbols and prevsymbol >= 0:
            # The code names the entry it is about to define: previous
            # string plus its own first byte.
            string = string_of(prevsymbol)
            string = string + string[:1]
        else:
            raise CorruptError("LZW: code %d out of range" % code)
        out += string
        first = string[0]
        if prevsymbol >= 0 and numsymbols < maxsymbols:
            parent[numsymbols] = prevsymbol
            chr_[numsymbols] = first
            len_[numsymbols] = len_[prevsymbol] + 1
            numsymbols += 1
            if numsymbols < maxsymbols and (numsymbols & (numsymbols - 1)) == 0:
                symbolsize += 1
        prevsymbol = code
    return bytes(out[:out_len])
