"""Unix compress (.Z) reader.

Three-byte header: ``1f 9d``, then the flags byte — the low 5 bits are
the maximum code width (9..16) and bit 0x80 the block bit (a clear code
resets the table). The format stores no size and no name; the entry is
named from the ``filename`` hint (a trailing ``.Z``/``.z`` is stripped,
as the reference readers derive the name from the archive's).
"""

from .._core import Archive, Entry
from .._lzw import lzw_decompress_all
from ..errors import CorruptError

OUTPUT_CAP = 1024 * 1024 * 1024  # 1 GiB ceiling, .Z has no size field


def probe(data):
    if len(data) < 3:
        return 0
    if data[0] != 0x1F or data[1] != 0x9D:
        return 0
    maxbits = data[2] & 0x1F
    if maxbits < 9 or maxbits > 16:
        return 0
    return 80


def open_data(data, password=None, filename=None):
    if len(data) < 3:
        raise CorruptError("Unix compress: file is too small")
    if data[0] != 0x1F or data[1] != 0x9D:
        raise CorruptError("Unix compress: not a .Z file")
    flags = data[2]
    maxbits = flags & 0x1F
    if maxbits < 9 or maxbits > 16:
        raise CorruptError("Unix compress: maxbits %d is out of range" % maxbits)
    blockmode = bool(flags & 0x80)
    decoded = lzw_decompress_all(data, maxbits=maxbits, blockmode=blockmode,
                                 offset=3, out_cap=OUTPUT_CAP)

    archive = Archive()
    archive.format = "Unix compress"
    if filename and isinstance(filename, str):
        import os
        leaf = os.path.basename(filename)
        if leaf.lower().endswith((".z",)):
            leaf = leaf[:-2] or "uncompressed"
        name = leaf or "uncompressed"
    else:
        name = "uncompressed"
    entry = Entry(name=name)
    entry._data = decoded
    entry.data_size = len(decoded)
    entry.resource_size = 0
    archive.entries.append(entry)
    return archive
