"""Bit-serialized Huffman tree, as used by PackIt's compressed entries,
StuffIt classic method 3 and DiskDoubler method 4.

Bits are read most-significant first within each byte, the stream
running forward.

The tree, in pre-order, one bit per node:

  1 — a leaf, followed by 8 bits (MSB first): the symbol
  0 — an internal node, followed by its zero subtree, then its one
      subtree

There is no end-of-stream marker and no count: the caller states how
many symbols it wants. A degenerate bare leaf consumes no bits per
symbol; the caller's count alone terminates decoding.

Facts from the format's own output (see the project's serialized-
huffman-tree note); no code was copied.
"""

from .errors import CorruptError


class BitReader:
    def __init__(self, data, offset=0):
        self.data = data
        self.bit = offset * 8

    def read_bit(self):
        if self.bit >= len(self.data) * 8:
            raise CorruptError("Huffman: bit stream exhausted")
        byte = self.data[self.bit >> 3]
        value = (byte >> (7 - (self.bit & 7))) & 1
        self.bit += 1
        return value

    def read_bits(self, count):
        value = 0
        for _ in range(count):
            value = (value << 1) | self.read_bit()
        return value


def _read_tree(reader, budget):
    """Read a tree; returns a node. node is ('leaf', symbol) or
    ('node', zero, one)."""
    if budget[0] <= 0:
        raise CorruptError("Huffman: more than 256 leaves")
    if reader.read_bit():
        budget[0] -= 1
        return ("leaf", reader.read_bits(8))
    zero = _read_tree(reader, budget)
    one = _read_tree(reader, budget)
    return ("node", zero, one)


class HuffmanDecoder:
    """Stateful decoder over one coded stream (the tree is read once,
    on construction). Use :meth:`decode` to pull any number of symbols.
    """

    def __init__(self, data, offset=0):
        self.reader = BitReader(data, offset)
        self.root = _read_tree(self.reader, [256])

    @property
    def next_byte_offset(self):
        return (self.reader.bit + 7) // 8

    def decode(self, symbol_count):
        if symbol_count < 0:
            raise CorruptError("Huffman: symbol count must not be negative")
        out = bytearray()
        if self.root[0] == "leaf":
            out += bytes([self.root[1]]) * symbol_count
            return bytes(out)
        root = self.root
        while len(out) < symbol_count:
            node = root
            while node[0] != "leaf":
                node = node[1] if self.reader.read_bit() == 0 else node[2]
            out.append(node[1])
        return bytes(out)


def decode(data, symbol_count, offset=0):
    """One-shot decode. Returns (payload_bytes, byte offset just past
    the last bit consumed, rounded up to a byte boundary)."""
    decoder = HuffmanDecoder(data, offset)
    payload = decoder.decode(symbol_count)
    return payload, decoder.next_byte_offset
