"""StuffIt classic method 13: a 64 KB LZSS window plus canonical
Huffman codes, in a bit stream read least-significant-bit first.

A leading selector byte picks the codes:

  0   the three code-length arrays are read from the stream itself, a
      fixed meta code coding the arrays; bit 3 (0x08) says the second
      literal/length code repeats the first, and the low three bits
      plus ten give the offset code's size (10..17 symbols)
  1..5   one of five predefined sets

Two literal/length codes of 321 symbols (0..255 literal; 256..317 a
match of 3..64 bytes; 318/319 a match of 65+ with 10/15 extra bits) and
one offset code whose symbol is the number of offset bits — the value's
high bit is implied, and the value counts from the byte about to be
written, so the distance is that value plus one.  After a literal the
first code is used; after a match the second.

Bit order: bytes are read least-significant bit first, and a canonical
code's most significant bit leaves the stream first (the codes are
stored bit-reversed, as zlib does).  Meta-code values leave
least-significant bit first.

From the format's published description (The Unarchiver wiki,
StuffItAlgorithm13, including its "in addition" rule for meta values
34/35/36 and a match distance one further back than the page says) and
the tested behavior of the parent MacExtract project; no code was
copied.  The five predefined length tables and the meta code are the
published ones.
"""

from .errors import CorruptError

FIRST_LENGTHS_1 = (
    4, 5, 7, 8, 8, 9, 9, 9, 9, 7, 9, 9, 9, 8, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 10, 9, 9, 10, 10, 9, 10, 9, 9,
    5, 9, 9, 9, 9, 10, 9, 9, 9, 9, 9, 9, 9, 9, 7, 9,
    9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 8, 9, 9, 8, 8, 9, 9, 9, 9, 9, 9, 9, 7, 8, 9,
    7, 9, 9, 7, 7, 9, 9, 9, 9, 10, 9, 10, 10, 10, 9, 9,
    9, 5, 9, 8, 7, 5, 9, 8, 8, 7, 9, 9, 8, 8, 5, 5,
    7, 10, 5, 8, 5, 8, 9, 9, 9, 9, 9, 10, 9, 9, 10, 9,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 9, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 9, 10, 9, 5,
    6, 5, 5, 8, 9, 9, 9, 9, 9, 9, 10, 10, 10, 9, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 9, 10, 9, 9, 9, 10, 9, 10, 9, 10, 9, 10, 9,
    10, 10, 10, 9, 10, 9, 10, 10, 9, 9, 9, 6, 9, 9, 10, 9,
    5,
)

SECOND_LENGTHS_1 = (
    4, 5, 6, 6, 7, 7, 6, 7, 7, 7, 6, 8, 7, 8, 8, 8,
    8, 9, 6, 9, 8, 9, 8, 9, 9, 9, 8, 10, 5, 9, 7, 9,
    6, 9, 8, 10, 9, 10, 8, 8, 9, 9, 7, 9, 8, 9, 8, 9,
    8, 8, 6, 9, 9, 8, 8, 9, 9, 10, 8, 9, 9, 10, 8, 10,
    8, 8, 8, 8, 8, 9, 7, 10, 6, 9, 9, 11, 7, 8, 8, 9,
    8, 10, 7, 8, 6, 9, 10, 9, 9, 10, 8, 11, 9, 11, 9, 10,
    9, 8, 9, 8, 8, 8, 8, 10, 9, 9, 10, 10, 8, 9, 8, 8,
    8, 11, 9, 8, 8, 9, 9, 10, 8, 11, 10, 10, 8, 10, 9, 10,
    8, 9, 9, 11, 9, 11, 9, 10, 10, 11, 10, 12, 9, 12, 10, 11,
    10, 11, 9, 10, 10, 11, 10, 11, 10, 11, 10, 11, 10, 10, 10, 9,
    9, 9, 8, 7, 6, 8, 11, 11, 9, 12, 10, 12, 9, 11, 11, 11,
    10, 12, 11, 11, 10, 12, 10, 11, 10, 10, 10, 11, 10, 11, 11, 11,
    9, 12, 10, 12, 11, 12, 10, 11, 10, 12, 11, 12, 11, 12, 11, 12,
    10, 12, 11, 12, 11, 11, 10, 12, 10, 11, 10, 12, 10, 12, 10, 12,
    10, 11, 11, 11, 10, 11, 11, 11, 10, 12, 11, 12, 10, 10, 11, 11,
    9, 12, 11, 12, 10, 11, 10, 12, 10, 11, 10, 12, 10, 11, 10, 7,
    5, 4, 6, 6, 7, 7, 7, 8, 8, 7, 7, 6, 8, 6, 7, 7,
    9, 8, 9, 9, 10, 11, 11, 11, 12, 11, 10, 11, 12, 11, 12, 11,
    12, 12, 12, 12, 11, 12, 12, 11, 12, 11, 12, 11, 13, 11, 12, 10,
    13, 10, 14, 14, 13, 14, 15, 14, 16, 15, 15, 18, 18, 18, 9, 18,
    8,
)

OFFSET_LENGTHS_1 = (
    5, 6, 3, 3, 3, 3, 3, 3, 3, 4, 6,
)

FIRST_LENGTHS_2 = (
    4, 7, 7, 8, 7, 8, 8, 8, 8, 7, 8, 7, 8, 7, 9, 8,
    8, 8, 9, 9, 9, 9, 10, 10, 9, 10, 10, 10, 10, 10, 9, 9,
    5, 9, 8, 9, 9, 11, 10, 9, 8, 9, 9, 9, 8, 9, 7, 8,
    8, 8, 9, 9, 9, 9, 9, 10, 9, 9, 9, 10, 9, 9, 10, 9,
    8, 8, 7, 7, 7, 8, 8, 9, 8, 8, 9, 9, 8, 8, 7, 8,
    7, 10, 8, 7, 7, 9, 9, 9, 9, 10, 10, 11, 11, 11, 10, 9,
    8, 6, 8, 7, 7, 5, 7, 7, 7, 6, 9, 8, 6, 7, 6, 6,
    7, 9, 6, 6, 6, 7, 8, 8, 8, 8, 9, 10, 9, 10, 9, 9,
    8, 9, 10, 10, 9, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 11, 10, 10, 10, 10, 10, 10, 10, 11, 10, 11, 10, 10,
    9, 11, 10, 10, 10, 10, 10, 10, 9, 9, 10, 11, 10, 11, 10, 11,
    10, 12, 10, 11, 10, 12, 11, 12, 10, 12, 10, 11, 10, 11, 11, 11,
    9, 10, 11, 11, 11, 12, 12, 10, 10, 10, 11, 11, 10, 11, 10, 10,
    9, 11, 10, 11, 10, 11, 11, 11, 10, 11, 11, 12, 11, 11, 10, 10,
    10, 11, 10, 10, 11, 11, 12, 10, 10, 11, 11, 12, 11, 11, 10, 11,
    9, 12, 10, 11, 11, 11, 10, 11, 10, 11, 10, 11, 9, 10, 9, 7,
    3, 5, 6, 6, 7, 7, 8, 8, 8, 9, 9, 9, 11, 10, 10, 10,
    12, 13, 11, 12, 12, 11, 13, 12, 12, 11, 12, 12, 13, 12, 14, 13,
    14, 13, 15, 13, 14, 15, 15, 14, 13, 15, 15, 14, 15, 14, 15, 15,
    14, 15, 13, 13, 14, 15, 15, 14, 14, 16, 16, 15, 15, 15, 12, 15,
    10,
)

SECOND_LENGTHS_2 = (
    5, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 8, 7, 8, 7, 7,
    7, 8, 8, 8, 8, 9, 8, 9, 8, 9, 9, 9, 7, 9, 8, 8,
    6, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 8,
    8, 8, 8, 9, 8, 9, 8, 9, 9, 10, 8, 10, 8, 9, 9, 8,
    8, 8, 7, 8, 8, 9, 8, 9, 7, 9, 8, 10, 8, 9, 8, 9,
    8, 9, 8, 8, 8, 9, 9, 9, 9, 10, 9, 11, 9, 10, 9, 10,
    8, 8, 8, 9, 8, 8, 8, 9, 9, 8, 9, 10, 8, 9, 8, 8,
    8, 11, 8, 7, 8, 9, 9, 9, 9, 10, 9, 10, 9, 10, 9, 8,
    8, 9, 9, 10, 9, 10, 9, 10, 8, 10, 9, 10, 9, 11, 10, 11,
    9, 11, 10, 10, 10, 11, 9, 11, 9, 10, 9, 11, 9, 11, 10, 10,
    9, 10, 9, 9, 8, 10, 9, 11, 9, 9, 9, 11, 10, 11, 9, 11,
    9, 11, 9, 11, 10, 11, 10, 11, 10, 11, 9, 10, 10, 11, 10, 10,
    8, 10, 9, 10, 10, 11, 9, 11, 9, 10, 10, 11, 9, 10, 10, 9,
    9, 10, 9, 10, 9, 10, 9, 10, 9, 11, 9, 11, 10, 10, 9, 10,
    9, 11, 9, 11, 9, 11, 9, 10, 9, 11, 9, 11, 9, 11, 9, 10,
    8, 11, 9, 10, 9, 10, 9, 10, 8, 10, 8, 9, 8, 9, 8, 7,
    4, 4, 5, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 7, 8, 8,
    9, 9, 10, 10, 10, 10, 10, 10, 11, 11, 10, 10, 12, 11, 11, 12,
    12, 11, 12, 12, 11, 12, 12, 12, 12, 12, 12, 11, 12, 11, 13, 12,
    13, 12, 13, 14, 14, 14, 15, 13, 14, 13, 14, 18, 18, 17, 7, 16,
    9,
)

OFFSET_LENGTHS_2 = (
    5, 6, 4, 4, 3, 3, 3, 3, 3, 4, 4, 4, 6,
)

FIRST_LENGTHS_3 = (
    6, 6, 6, 6, 6, 9, 8, 8, 4, 9, 8, 9, 8, 9, 9, 9,
    8, 9, 9, 10, 8, 10, 10, 10, 9, 10, 10, 10, 9, 10, 10, 9,
    9, 9, 8, 10, 9, 10, 9, 10, 9, 10, 9, 10, 9, 9, 8, 9,
    8, 9, 9, 9, 10, 10, 10, 10, 9, 9, 9, 10, 9, 10, 9, 9,
    7, 8, 8, 9, 8, 9, 9, 9, 8, 9, 9, 10, 9, 9, 8, 9,
    8, 9, 8, 8, 8, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 9,
    8, 8, 9, 8, 9, 7, 8, 8, 9, 8, 10, 10, 8, 9, 8, 8,
    8, 10, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 10, 9,
    7, 9, 9, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 9,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 9, 9, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 9,
    8, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9,
    9, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 9, 9,
    9, 10, 10, 10, 10, 10, 10, 9, 9, 10, 9, 9, 8, 9, 8, 9,
    4, 6, 6, 6, 7, 8, 8, 9, 9, 10, 10, 10, 9, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 7, 10,
    10, 10, 7, 10, 10, 7, 7, 7, 7, 7, 6, 7, 10, 7, 7, 10,
    7, 7, 7, 6, 7, 6, 6, 7, 7, 6, 6, 9, 6, 9, 10, 6,
    10,
)

SECOND_LENGTHS_3 = (
    5, 6, 6, 6, 6, 7, 7, 7, 6, 8, 7, 8, 7, 9, 8, 8,
    7, 7, 8, 9, 9, 9, 9, 10, 8, 9, 9, 10, 8, 10, 9, 8,
    6, 10, 8, 10, 8, 10, 9, 9, 9, 9, 9, 10, 9, 9, 8, 9,
    8, 9, 8, 9, 9, 10, 9, 10, 9, 9, 8, 10, 9, 11, 10, 8,
    8, 8, 8, 9, 7, 9, 9, 10, 8, 9, 8, 11, 9, 10, 9, 10,
    8, 9, 9, 9, 9, 8, 9, 9, 10, 10, 10, 12, 10, 11, 10, 10,
    8, 9, 9, 9, 8, 9, 8, 8, 10, 9, 10, 11, 8, 10, 9, 9,
    8, 12, 8, 9, 9, 9, 9, 8, 9, 10, 9, 12, 10, 10, 10, 8,
    7, 11, 10, 9, 10, 11, 9, 11, 7, 11, 10, 12, 10, 12, 10, 11,
    9, 11, 9, 12, 10, 12, 10, 12, 10, 9, 11, 12, 10, 12, 10, 11,
    9, 10, 9, 10, 9, 11, 11, 12, 9, 10, 8, 12, 11, 12, 9, 12,
    10, 12, 10, 13, 10, 12, 10, 12, 10, 12, 10, 9, 10, 12, 10, 9,
    8, 11, 10, 12, 10, 12, 10, 12, 10, 11, 10, 12, 8, 12, 10, 11,
    10, 10, 10, 12, 9, 11, 10, 12, 10, 12, 11, 12, 10, 9, 10, 12,
    9, 10, 10, 12, 10, 11, 10, 11, 10, 12, 8, 12, 9, 12, 8, 12,
    8, 11, 10, 11, 10, 11, 9, 10, 8, 10, 9, 9, 8, 9, 8, 7,
    4, 3, 5, 5, 6, 5, 6, 6, 7, 7, 8, 8, 8, 7, 7, 7,
    9, 8, 9, 9, 11, 9, 11, 9, 8, 9, 9, 11, 12, 11, 12, 12,
    13, 13, 12, 13, 14, 13, 14, 13, 14, 13, 13, 13, 12, 13, 13, 12,
    13, 13, 14, 14, 13, 13, 14, 14, 14, 14, 15, 18, 17, 18, 8, 16,
    10,
)

OFFSET_LENGTHS_3 = (
    6, 7, 4, 4, 3, 3, 3, 3, 3, 4, 4, 4, 5, 7,
)

FIRST_LENGTHS_4 = (
    2, 6, 6, 7, 7, 8, 7, 8, 7, 8, 8, 9, 8, 9, 9, 9,
    8, 8, 9, 9, 9, 10, 10, 9, 8, 10, 9, 10, 9, 10, 9, 9,
    6, 9, 8, 9, 9, 10, 9, 9, 9, 10, 9, 9, 9, 9, 8, 8,
    8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 9,
    7, 7, 8, 8, 8, 8, 9, 9, 7, 8, 9, 10, 8, 8, 7, 8,
    8, 10, 8, 8, 8, 9, 8, 9, 9, 10, 9, 11, 10, 11, 9, 9,
    8, 7, 9, 8, 8, 6, 8, 8, 8, 7, 10, 9, 7, 8, 7, 7,
    8, 10, 7, 7, 7, 8, 9, 9, 9, 9, 10, 11, 9, 11, 10, 9,
    7, 9, 10, 10, 10, 11, 11, 10, 10, 11, 10, 10, 10, 11, 11, 10,
    9, 10, 10, 11, 10, 11, 10, 11, 10, 10, 10, 11, 10, 11, 10, 10,
    9, 10, 10, 11, 10, 10, 10, 10, 9, 10, 10, 10, 10, 11, 10, 11,
    10, 11, 10, 11, 11, 11, 10, 12, 10, 11, 10, 11, 10, 11, 11, 10,
    8, 10, 10, 11, 10, 11, 11, 11, 10, 11, 10, 11, 10, 11, 11, 11,
    9, 10, 11, 11, 10, 11, 11, 11, 10, 11, 11, 11, 10, 10, 10, 10,
    10, 11, 10, 10, 11, 11, 10, 10, 9, 11, 10, 10, 11, 11, 10, 10,
    10, 11, 10, 10, 10, 10, 10, 10, 9, 11, 10, 10, 8, 10, 8, 6,
    5, 6, 6, 7, 7, 8, 8, 8, 9, 10, 11, 10, 10, 11, 11, 12,
    12, 10, 11, 12, 12, 12, 12, 13, 13, 13, 13, 13, 12, 13, 13, 15,
    14, 12, 14, 15, 16, 12, 12, 13, 15, 14, 16, 15, 17, 18, 15, 17,
    16, 15, 15, 15, 15, 13, 13, 10, 14, 12, 13, 17, 17, 18, 10, 17,
    4,
)

SECOND_LENGTHS_4 = (
    4, 5, 6, 6, 6, 6, 7, 7, 6, 7, 7, 9, 6, 8, 8, 7,
    7, 8, 8, 8, 6, 9, 8, 8, 7, 9, 8, 9, 8, 9, 8, 9,
    6, 9, 8, 9, 8, 10, 9, 9, 8, 10, 8, 10, 8, 9, 8, 9,
    8, 8, 7, 9, 9, 9, 9, 9, 8, 10, 9, 10, 9, 10, 9, 8,
    7, 8, 9, 9, 8, 9, 9, 9, 7, 10, 9, 10, 9, 9, 8, 9,
    8, 9, 8, 8, 8, 9, 9, 10, 9, 9, 8, 11, 9, 11, 10, 10,
    8, 8, 10, 8, 8, 9, 9, 9, 10, 9, 10, 11, 9, 9, 9, 9,
    8, 9, 8, 8, 8, 10, 10, 9, 9, 8, 10, 11, 10, 11, 11, 9,
    8, 9, 10, 11, 9, 10, 11, 11, 9, 12, 10, 10, 10, 12, 11, 11,
    9, 11, 11, 12, 9, 11, 9, 10, 10, 10, 10, 12, 9, 11, 10, 11,
    9, 11, 11, 11, 10, 11, 11, 12, 9, 10, 10, 12, 11, 11, 10, 11,
    9, 11, 10, 11, 10, 11, 9, 11, 11, 9, 8, 11, 10, 11, 11, 10,
    7, 12, 11, 11, 11, 11, 11, 12, 10, 12, 11, 13, 11, 10, 12, 11,
    10, 11, 10, 11, 10, 11, 11, 11, 10, 12, 11, 11, 10, 11, 10, 10,
    10, 11, 10, 12, 11, 12, 10, 11, 9, 11, 10, 11, 10, 11, 10, 12,
    9, 11, 11, 11, 9, 11, 10, 10, 9, 11, 10, 10, 9, 10, 9, 7,
    4, 5, 5, 5, 6, 6, 7, 6, 8, 7, 8, 9, 9, 7, 8, 8,
    10, 9, 10, 10, 12, 10, 11, 11, 11, 11, 10, 11, 12, 11, 11, 11,
    11, 11, 13, 12, 11, 12, 13, 12, 12, 12, 13, 11, 9, 12, 13, 7,
    13, 11, 13, 11, 10, 11, 13, 15, 15, 12, 14, 15, 15, 15, 6, 15,
    5,
)

OFFSET_LENGTHS_4 = (
    3, 6, 5, 4, 2, 3, 3, 3, 4, 4, 6,
)

FIRST_LENGTHS_5 = (
    7, 9, 9, 9, 9, 9, 9, 9, 9, 8, 9, 9, 9, 7, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 10, 9, 10, 9, 10, 9, 10, 9, 9,
    5, 9, 7, 9, 9, 9, 9, 9, 7, 7, 7, 9, 7, 7, 8, 7,
    8, 8, 7, 7, 9, 9, 9, 9, 7, 7, 7, 9, 9, 9, 9, 9,
    9, 7, 9, 7, 7, 7, 7, 9, 9, 7, 9, 9, 7, 7, 7, 7,
    7, 9, 7, 8, 7, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 7, 8, 7, 7, 7, 8, 8, 6, 7, 9, 7, 7, 8, 7, 5,
    6, 9, 5, 7, 5, 6, 7, 7, 9, 8, 9, 9, 9, 9, 9, 9,
    9, 9, 10, 9, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10,
    9, 10, 10, 10, 9, 9, 10, 9, 9, 9, 9, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 9, 10, 10, 10, 9, 9, 9, 10, 10, 10, 10, 10,
    9, 10, 9, 10, 10, 9, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 9, 10, 9, 10, 10, 9,
    5, 6, 8, 8, 7, 7, 7, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 5, 10, 8, 9, 8,
    9,
)

SECOND_LENGTHS_5 = (
    8, 10, 11, 11, 11, 12, 11, 11, 12, 6, 11, 12, 10, 5, 12, 12,
    12, 12, 12, 12, 12, 13, 13, 14, 13, 13, 12, 13, 12, 13, 12, 15,
    4, 10, 7, 9, 11, 11, 10, 9, 6, 7, 8, 9, 6, 7, 6, 7,
    8, 7, 7, 8, 8, 8, 8, 8, 8, 9, 8, 7, 10, 9, 10, 10,
    11, 7, 8, 6, 7, 8, 8, 9, 8, 7, 10, 10, 8, 7, 8, 8,
    7, 10, 7, 6, 7, 9, 9, 8, 11, 11, 11, 10, 11, 11, 11, 8,
    11, 6, 7, 6, 6, 6, 6, 8, 7, 6, 10, 9, 6, 7, 6, 6,
    7, 10, 6, 5, 6, 7, 7, 7, 10, 8, 11, 9, 13, 7, 14, 16,
    12, 14, 14, 15, 15, 16, 16, 14, 15, 15, 15, 15, 15, 15, 15, 15,
    14, 15, 13, 14, 14, 16, 15, 17, 14, 17, 15, 17, 12, 14, 13, 16,
    12, 17, 13, 17, 14, 13, 13, 14, 14, 12, 13, 15, 15, 14, 15, 17,
    14, 17, 15, 14, 15, 16, 12, 16, 15, 14, 15, 16, 15, 16, 17, 17,
    15, 15, 17, 17, 13, 14, 15, 15, 13, 12, 16, 16, 17, 14, 15, 16,
    15, 15, 13, 13, 15, 13, 16, 17, 15, 17, 17, 17, 16, 17, 14, 17,
    14, 16, 15, 17, 15, 15, 14, 17, 15, 17, 15, 16, 15, 15, 16, 16,
    14, 17, 17, 15, 15, 16, 15, 17, 15, 14, 16, 16, 16, 16, 16, 12,
    4, 4, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 8, 9, 9,
    9, 9, 9, 10, 10, 10, 11, 10, 11, 11, 11, 11, 11, 12, 12, 12,
    13, 13, 12, 13, 12, 14, 14, 12, 13, 13, 13, 13, 14, 12, 13, 13,
    14, 14, 14, 13, 14, 14, 15, 15, 13, 15, 13, 17, 17, 17, 9, 17,
    7,
)

OFFSET_LENGTHS_5 = (
    6, 7, 7, 6, 4, 3, 2, 2, 3, 3, 6,
)

META_CODES = (
    0x5d8, 0x058, 0x040, 0x0c0, 0x000, 0x078, 0x02b, 0x014,
    0x00c, 0x01c, 0x01b, 0x00b, 0x010, 0x020, 0x038, 0x018,
    0x0d8, 0xbd8, 0x180, 0x680, 0x380, 0xf80, 0x780, 0x480,
    0x080, 0x280, 0x3d8, 0xfd8, 0x7d8, 0x9d8, 0x1d8, 0x004,
    0x001, 0x002, 0x007, 0x003, 0x008,
)

META_LENGTHS = (
    11, 8, 8, 8, 8, 7, 6, 5, 5, 5, 5, 6, 5, 6, 7, 7,
    9, 12, 10, 11, 11, 12, 12, 11, 11, 11, 12, 12, 12, 12, 12, 5,
    2, 2, 3, 4, 5,
)
OFFSET_CODESIZES = (11, 13, 14, 11, 11)

FIRST_LENGTHS = (
    FIRST_LENGTHS_1, FIRST_LENGTHS_2, FIRST_LENGTHS_3,
    FIRST_LENGTHS_4, FIRST_LENGTHS_5,
)
SECOND_LENGTHS = (
    SECOND_LENGTHS_1, SECOND_LENGTHS_2, SECOND_LENGTHS_3,
    SECOND_LENGTHS_4, SECOND_LENGTHS_5,
)
OFFSET_LENGTHS = (
    OFFSET_LENGTHS_1, OFFSET_LENGTHS_2, OFFSET_LENGTHS_3,
    OFFSET_LENGTHS_4, OFFSET_LENGTHS_5,
)

ALPHABET = 321          # literal/length symbols per code
WINDOW = 65536
END_SYMBOL = 320


class _Canon:
    """Canonical codes built from per-symbol lengths (0 = unused)."""

    __slots__ = ("first", "count", "sym", "maxlen")

    def __init__(self, first, count, sym, maxlen):
        self.first = first    # first code value per bit length
        self.count = count    # codes per bit length
        self.sym = sym        # symbols in (length, symbol) order
        self.maxlen = maxlen


def _build(lengths):
    count = [0] * 32
    maxlen = 0
    for value in lengths:
        if value == 0:
            continue
        if value > 31:
            raise CorruptError(
                "StuffIt 13: code length %d is out of range" % value)
        count[value] += 1
        if value > maxlen:
            maxlen = value
    # One bit doubles the codes available; spending more than that is
    # over-subscription and the lengths cannot be a prefix code.  Some
    # left over (incomplete) is allowed.  Python integers do not wrap,
    # so no signed-overflow subtlety here.
    first = [0] * 32
    code = 0
    left = 1
    for length in range(1, maxlen + 1):
        first[length] = code
        code = (code + count[length]) << 1
        left <<= 1
        if count[length] > left:
            raise CorruptError("StuffIt 13: code lengths over-subscribed")
        left -= count[length]
    starts = [0] * 33
    for length in range(1, maxlen):
        starts[length + 1] = starts[length] + count[length]
    sym = [0] * sum(count)
    for index, length in enumerate(lengths):
        if length:
            sym[starts[length]] = index
            starts[length] += 1
    return _Canon(first, count, sym, maxlen)


def canonical_codes(lengths):
    """The encoder side of :func:`_build`: a ``(bit length, code
    value)`` tuple per symbol, or ``None`` for an unused one."""
    canon = _build(lengths)
    starts = [0] * 33
    for length in range(1, canon.maxlen):
        starts[length + 1] = starts[length] + canon.count[length]
    codes = [None] * len(lengths)
    for length in range(1, canon.maxlen + 1):
        for k in range(canon.count[length]):
            codes[canon.sym[starts[length] + k]] = (
                length, canon.first[length] + k)
    return codes


class _LsbReader:
    """Bit reader: each byte's least significant bit first."""

    __slots__ = ("data", "pos", "end", "bit")

    def __init__(self, data, offset=0, limit=None):
        self.data = data
        self.pos = offset
        self.end = len(data) if limit is None else offset + limit
        self.bit = 0

    def read_bit(self):
        if self.pos >= self.end:
            raise CorruptError("StuffIt 13: bit stream exhausted")
        value = (self.data[self.pos] >> self.bit) & 1
        self.bit += 1
        if self.bit == 8:
            self.bit = 0
            self.pos += 1
        return value

    def read_bits(self, count):
        value = 0
        for index in range(count):
            value |= self.read_bit() << index
        return value


def _meta_symbol(reader):
    """One meta-code symbol: values leave least-significant bit first
    and are matched against the published table directly."""
    acc = 0
    for length in range(1, 13):
        acc |= reader.read_bit() << (length - 1)
        for index in range(37):
            if META_LENGTHS[index] == length and META_CODES[index] == acc:
                return index
    raise CorruptError("StuffIt 13: unknown meta code")


def _read_lengths(reader, nsyms):
    """Read ``nsyms`` code lengths through the meta code.

    Each meta value sets the running length variable and then writes
    that length to the next entry — except 34/35/36, which write their
    repeats *and* the next entry ("in addition", load-bearing: without
    it the arrays miss Kraft's equality).  A length variable of -1
    (meta value 31, the published "invalid code" marker) writes 0.
    """
    lengths = [0] * nsyms
    index = 0
    current = 0
    while index < nsyms:
        value = _meta_symbol(reader)
        if value < 31:
            current = value + 1
        elif value == 31:
            current = -1
        elif value == 32:
            current += 1
        elif value == 33:
            current -= 1
        elif value == 34:
            if reader.read_bit():
                if index >= nsyms:
                    raise CorruptError(
                        "StuffIt 13: code lengths run past the array")
                lengths[index] = current if current > 0 else 0
                index += 1
        else:
            repeat = (reader.read_bits(3) + 2 if value == 35
                      else reader.read_bits(6) + 10)
            while repeat:
                repeat -= 1
                if index >= nsyms:
                    raise CorruptError(
                        "StuffIt 13: code lengths run past the array")
                lengths[index] = current if current > 0 else 0
                index += 1
        if index >= nsyms:
            break
        lengths[index] = current if current > 0 else 0
        index += 1
    return lengths


def read_lengths(data, nsyms, offset=0):
    """Read one meta-coded code-length array from ``data`` at
    ``offset``.  Returns the list of ``nsyms`` lengths."""
    return _read_lengths(_LsbReader(data, offset), nsyms)


def _decode(canon, reader):
    """One canonical code.  The stream is read LSB-first per byte, and
    the code's most significant bit leaves it first, so accumulating
    ``code = (code << 1) | bit`` rebuilds the code value; the length's
    run of consecutive values then names the symbol."""
    code = 0
    base = 0
    for length in range(1, canon.maxlen + 1):
        code = (code << 1) | reader.read_bit()
        first = canon.first[length]
        count = canon.count[length]
        if first <= code < first + count:
            return canon.sym[base + code - first]
        base += count
    raise CorruptError("StuffIt 13: invalid Huffman code")


def sit13_decode(data, out_len):
    """Decode exactly ``out_len`` bytes from ``data``; returns them.
    Raises CorruptError on a bad selector, bad codes, an end marker
    before the fork's length, or a stream that runs out."""
    if out_len < 0:
        raise CorruptError("StuffIt 13: output length must not be negative")
    if out_len == 0:
        return b""
    if not data:
        raise CorruptError("StuffIt 13: selector byte missing")
    selector = data[0]
    reader = _LsbReader(data, 1)
    chosen = selector >> 4
    if chosen == 0:
        first = _build(_read_lengths(reader, ALPHABET))
        if selector & 0x08:
            second = first
        else:
            second = _build(_read_lengths(reader, ALPHABET))
        offset_tree = _build(_read_lengths(reader, (selector & 0x07) + 10))
    elif chosen <= 5:
        first = _build(FIRST_LENGTHS[chosen - 1])
        second = _build(SECOND_LENGTHS[chosen - 1])
        offset_tree = _build(OFFSET_LENGTHS[chosen - 1])
    else:
        raise CorruptError(
            "StuffIt 13: code selector %d is out of range" % chosen)

    window = bytearray(WINDOW)
    out = bytearray()
    pos = 0
    current = first
    while pos < out_len:
        symbol = _decode(current, reader)
        if symbol < 0x100:
            current = first
            window[pos & (WINDOW - 1)] = symbol
            out.append(symbol)
            pos += 1
            continue
        current = second
        if symbol < 0x13E:
            match_len = symbol - 0x100 + 3
        elif symbol == 0x13E:
            match_len = reader.read_bits(10) + 65
        elif symbol == 0x13F:
            match_len = reader.read_bits(15) + 65
        else:
            raise CorruptError(
                "StuffIt 13: end marker before the fork's length")
        bits = _decode(offset_tree, reader)
        if bits == 0:
            distance = 1
        elif bits == 1:
            distance = 2
        else:
            # The value's high bit is implied.
            distance = (1 << (bits - 1)) + reader.read_bits(bits - 1) + 1
        count = match_len
        if count > out_len - pos:
            count = out_len - pos
        # Overlapping matches copy byte by byte, window wraps included.
        for _ in range(count):
            value = window[(pos - distance) & (WINDOW - 1)]
            window[pos & (WINDOW - 1)] = value
            out.append(value)
            pos += 1
    return bytes(out)
