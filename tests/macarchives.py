"""Generators for synthetic archives used as test fixtures.

Everything here builds byte strings in memory; no binary fixtures are
committed. Writers aim to match the published formats, including the
weird corners the tests exercise.
"""

import hashlib
import struct
import zlib

from macextract import _sit13
from macextract._arsenic import HALF, MODELS, ONE, RNDTABLE, Model
from macextract._crc16 import crc16_arc, crc16_ccitt
from macextract._rc4 import rc4

MAC_EPOCH = 2082844800


def macbinary(name=b"TestFile", data=b"hello world", rsrc=b"", type=b"TEXT",
              creator=b"ttxt", version=129, flags=0, created=400000000,
              modified=400000100, comment=b"", secondary=b"",
              bad_crc=False, zero_pad=True):
    """Build a MacBinary image. ``version`` 0 = MB I, 129 = II, 130 = III."""
    name = bytes(name)
    header = bytearray(128)
    header[0] = 0
    header[1] = len(name)
    header[2:2 + len(name)] = name
    header[65:69] = type
    header[69:73] = creator
    header[73] = (flags >> 8) & 0xFF
    header[75:77] = struct.pack(">H", 10)   # window vertical
    header[77:79] = struct.pack(">H", 20)   # window horizontal
    header[79:81] = struct.pack(">H", 100)  # window/folder ID
    header[81] = 0
    struct.pack_into(">II", header, 83, len(data), len(rsrc))
    struct.pack_into(">II", header, 91, created, modified)
    if version >= 129:
        struct.pack_into(">H", header, 99, len(comment))
        header[101] = flags & 0xFF
        if version >= 130:
            struct.pack_into(">I", header, 116, 128 + len(data) + len(rsrc))
            struct.pack_into(">H", header, 120, len(secondary))
        header[122] = version
        header[123] = 129
        crc = crc16_ccitt(bytes(header[:124]))
        if bad_crc:
            crc ^= 0xFFFF
        struct.pack_into(">H", header, 124, crc)
    out = bytearray(header)
    if version >= 130 and secondary:
        sec = secondary.ljust(len(secondary) + (-len(secondary)) % 128, b"\0")
        out += sec
    pad = lambda n: (n + 127) & ~127
    data_part = data.ljust(pad(len(data)), b"\0")
    out += data_part
    out += rsrc.ljust(pad(len(rsrc)), b"\0")
    if comment:
        out += comment.ljust(pad(len(comment)), b"\0")
    return bytes(out)


BINHEX_ALPHABET = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr"


def binhex(name="TestFile", data=b"hello world", rsrc=b"", type=b"TEXT",
           creator=b"ttxt", flags=0, bad_header_crc=False, bad_data_crc=False,
           rle_marker_zero=True):
    """Build a BinHex 4.0 image in memory (test generator)."""
    name_bytes = name.encode("mac_roman") if isinstance(name, str) else name
    header = bytearray(b"\0")  # placeholder
    body = bytearray()
    body.append(len(name_bytes))
    body += name_bytes
    body.append(0)
    body += type + creator
    body += struct.pack(">H", flags)
    body += struct.pack(">II", len(data), len(rsrc))
    header_crc = crc16_ccitt(bytes(body) + b"\0\0")
    if bad_header_crc:
        header_crc ^= 0xFF
    body += struct.pack(">H", header_crc)

    data_crc = crc16_ccitt(data + b"\0\0")
    if bad_data_crc:
        data_crc ^= 0xFF
    body += data + struct.pack(">H", data_crc)

    rsrc_crc = crc16_ccitt(rsrc + b"\0\0")
    body += rsrc + struct.pack(">H", rsrc_crc)

    encoded = _binhex_rle(bytes(body))
    payload = _sixbit_encode(encoded)
    lines = []
    first = ":" + payload[:63]
    lines.append(first)
    rest = payload[63:]
    width = 64
    lines += [rest[i:i + width] for i in range(0, len(rest), width)]
    return ("(This file must be converted with BinHex 4.0)\n"
            + "\n".join(lines) + ":\n").encode("ascii")


def _binhex_rle(src):
    out = bytearray()
    i = 0
    while i < len(src):
        byte = src[i]
        if byte == 0x90:
            out += b"\x90\x00"
            i += 1
            continue
        run = 1
        while i + run < len(src) and src[i + run] == byte and run < 255:
            run += 1
        if run >= 3:
            out.append(byte)
            out.append(0x90)
            out.append(run)
            i += run
        else:
            out.append(byte)
            i += 1
    return bytes(out)


def _sixbit_encode(src):
    out = []
    acc = 0
    nbits = 0
    for byte in src:
        acc = (acc << 8) | byte
        nbits += 8
        while nbits >= 6:
            nbits -= 6
            out.append(BINHEX_ALPHABET[(acc >> nbits) & 0x3F])
    if nbits:
        out.append(BINHEX_ALPHABET[(acc << (6 - nbits)) & 0x3F])
    return "".join(out)


AS_EPOCH = __import__("datetime").datetime(2000, 1, 1, tzinfo=__import__("datetime").timezone.utc)


def applesingle_seconds(dt):
    delta = dt - AS_EPOCH
    return int(delta.total_seconds())


def applesingle(name=b"TestFile", data=b"hello world", rsrc=b"",
                type=b"TEXT", creator=b"ttxt", flags=0, created=None, modified=None,
                magic=0x00051600, version=0x00020000, macinfo=0x00,
                include_dates=True, include_finder=True, include_name=True):
    """Build an AppleSingle (or AppleDouble header, magic=0x00051607)."""
    entries = []
    if data is not None and magic == 0x00051600:
        entries.append((1, data))
    if rsrc:
        entries.append((2, rsrc))
    if include_name and name is not None:
        entries.append((3, bytes(name)))
    if include_dates:
        created = created if created is not None else applesingle_seconds(
            __import__("datetime").datetime(1993, 6, 1, tzinfo=__import__("datetime").timezone.utc))
        modified = modified if modified is not None else applesingle_seconds(
            __import__("datetime").datetime(1995, 11, 4, tzinfo=__import__("datetime").timezone.utc))
        entries.append((8, struct.pack(">iiii", created, modified, 0, 0)))
    if include_finder:
        finder = type + creator + struct.pack(">H", flags) + b"\0" * 22
        entries.append((9, finder))
    entries.append((10, b"\0\0\0" + bytes([macinfo])))

    header_size = 26 + 12 * len(entries)
    offset = header_size
    parts = []
    descriptors = []
    for entry_id, payload in entries:
        descriptors.append((entry_id, offset, len(payload)))
        offset += len(payload)
    parts.append(struct.pack(">II", magic, version) + b"\0" * 16)
    parts.append(struct.pack(">H", len(entries)))
    for entry_id, off, length in descriptors:
        parts.append(struct.pack(">III", entry_id, off, length))
    for _, payload in entries:
        parts.append(payload)
    return b"".join(parts)


def uuencode(name="TestFile", data=b"hello world", mode=0o644,
             rsrc=None, finfo=None, extra_segments=()):
    """Build a uuencode stream; optionally with MU-style fork sections."""
    segments = [(mode, name, data)]
    if rsrc is not None:
        segments.append((mode, name + ".rsrc", rsrc))
    if finfo is not None:
        segments.append((mode, name + ".finfo", finfo))
    segments.extend(extra_segments)
    out = []
    for seg_mode, seg_name, payload in segments:
        out.append("begin %03o %s" % (seg_mode, seg_name))
        i = 0
        while i < len(payload):
            chunk = payload[i:i + 45]
            i += len(chunk)
            line = chr(len(chunk) + 32)
            for j in range(0, len(chunk), 3):
                b = chunk[j:j + 3].ljust(3, b"\0")
                n = (b[0] << 16) | (b[1] << 8) | b[2]
                line += "".join(chr(((n >> shift) & 0x3F) + 32) for shift in (18, 12, 6, 0))
            out.append(line)
        out.append("`")
        out.append("end")
    return ("\n".join(out) + "\n").encode("ascii")


def btoa(name="file.txt", data=b"hello world", newver=True, bad_sum=False):
    """Build a .btoa image in memory (v4 or v5)."""
    lines_out = ["xbtoa5 78 %s Begin" % (name or "-") if newver else "xbtoa Begin"]
    eor = 0; total = 0; rot = 0
    def chk(ch):
        nonlocal eor, total, rot
        eor ^= ch
        total = (total + ch + 1) & 0xFFFFFFFF
        rot = (((rot << 1) | (rot >> 31)) & 0xFFFFFFFF) + ch
    body = []
    i = 0
    groups = []
    while i < len(data):
        quad = data[i:i+4]
        i += len(quad)
        full = len(quad) == 4
        groups.append((quad.ljust(4, b"\0"), full))
    if not groups:
        groups = []
    chars = []
    for padded, full in groups:
        if full and padded == b"\0\0\0\0":
            chars.append("z")
            continue
        if full and newver and padded == b" " * 4:
            chars.append("y")
            continue
        code = int.from_bytes(padded, "big")
        block = []
        for _ in range(5):
            block.append(code % 85 + 33)
            code //= 85
        chars.extend(chr(c) for c in reversed(block))
    perline = 78 if newver else 78
    line_chars = []
    lines = []
    for ch in chars:
        line_chars.append(ch)
        if len(line_chars) >= perline:
            lines.append(line_chars); line_chars = []
    if line_chars:
        lines.append(line_chars)
    for lc in lines:
        text = "".join(lc)
        for c in text:
            chk(ord(c))
        if newver:
            lines_out.append(text + chr(33 + (total % 85)))
        else:
            lines_out.append(text)
    if not newver:
        # version 4 checksums the decoded quad bytes (padding included)
        eor = 0; total = 0; rot = 0
        for padded, _full in groups:
            for b in padded:
                chk(b)
    want_hex = "%x" % len(data)
    if bad_sum:
        eor ^= 0xFF
    lines_out.append("xbtoa End N %d %s E %x S %x R %x" % (len(data), want_hex, eor, total, rot))
    return ("\n".join(lines_out) + "\n").encode("latin-1")


import base64 as _b64mod


def base64_begin(name="TestFile", data=b"hello world", mode=0o644):
    encoded = _b64mod.b64encode(data).decode()
    lines = [encoded[i:i + 76] for i in range(0, len(encoded), 76)]
    return ("begin-base64 %03o %s\n%s\n====\n" % (mode, name, "\n".join(lines))).encode("ascii")


def base64_bare(data=b"hello world"):
    encoded = _b64mod.b64encode(data).decode()
    lines = [encoded[i:i + 76] for i in range(0, len(encoded), 76)]
    return ("\n".join(lines) + "\n").encode("ascii")


def mime_message(parts, boundary="Apple-Mail-Boundary",
                 preamble="This is the message body.\n",
                 headers=None):
    if headers is None:
        headers = ("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n" % boundary)
    out = [headers.rstrip("\r\n"), ""]
    if preamble:
        out.append(preamble.rstrip("\n"))
    for part in parts:
        out.append("--" + boundary)
        out.append(part.get("headers", ""))
        out.append("")
        out.append(part["body"])
    out.append("--" + boundary + "--")
    return "\r\n".join(out).encode("latin-1")


def mime_b64_part(filename, data, ctype="application/octet-stream"):
    encoded = _b64mod.b64encode(data).decode()
    lines = [encoded[i:i + 76] for i in range(0, len(encoded), 76)]
    return {
        "headers": ("Content-Type: %s; name=\"%s\"\r\n"
                    "Content-Transfer-Encoding: base64\r\n"
                    "Content-Disposition: attachment; filename=\"%s\"" % (ctype, filename, filename)),
        "body": "\r\n".join(lines),
    }


def appledouble_part_headers():
    return ("Content-Type: application/applefile\r\n"
            "Content-Transfer-Encoding: base64")


def mime_appledouble(name=b"Doc", data=b"data-fork-bytes", rsrc=b"rsrc-bytes",
                     type=b"TEXT", creator=b"ttxt"):
    applefile = applesingle(name=name, data=None, rsrc=rsrc,
                            type=type, creator=creator,
                            magic=0x00051607)
    first = {
        "headers": appledouble_part_headers(),
        "body": "\r\n".join(_b64mod.b64encode(applefile).decode()[i:i + 76]
                          for i in range(0, len(_b64mod.b64encode(applefile).decode()), 76)),
    }
    second = {
        "headers": ("Content-Type: application/octet-stream\r\n"
                    "Content-Transfer-Encoding: base64"),
        "body": "\r\n".join(_b64mod.b64encode(data).decode()[i:i + 76]
                          for i in range(0, len(_b64mod.b64encode(data).decode()), 76)),
    }
    boundary = "AppleMailBoundary"
    headers = ("MIME-Version: 1.0\r\n"
               "Content-Type: multipart/appledouble; boundary=\"%s\"\r\n" % boundary)
    return mime_message([first, second], boundary=boundary, headers=headers, preamble="")


import heapq
from collections import Counter


def huffman_encode(payload):
    """Encode bytes as a bit-serialized Huffman stream (tree + codes),
    matching the layout the PackIt reader (and StuffIt method 3 /
    DiskDoubler method 4) consumes. Test-side counterpart only."""
    if not payload:
        raise ValueError("huffman_encode needs at least one byte")
    freq = Counter(payload)
    heap = [(weight, index, ("leaf", symbol)) for index, (symbol, weight)
            in enumerate(sorted(freq.items()))]
    heapq.heapify(heap)
    counter = len(heap)
    while len(heap) > 1:
        weight_a, _, node_a = heapq.heappop(heap)
        weight_b, _, node_b = heapq.heappop(heap)
        heapq.heappush(heap, (weight_a + weight_b, counter,
                              ("node", node_a, node_b)))
        counter += 1
    root = heap[0][2]

    def serialize(node):
        if node[0] == "leaf":
            return "1" + format(node[1], "08b")
        return "0" + serialize(node[1]) + serialize(node[2])

    bits = serialize(root)
    if root[0] != "leaf":
        codes = {}

        def assign(node, prefix):
            if node[0] == "leaf":
                codes[node[1]] = prefix
                return
            assign(node[1], prefix + "0")
            assign(node[2], prefix + "1")

        assign(root, "")
        bits += "".join(codes[byte] for byte in payload)
    pad = (-len(bits)) % 8
    bits += "0" * pad
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _packit_header(name, data_len, rsrc_len, type=b"TEXT", creator=b"TTxt",
                   flags=0x0100, locked=False, created=400000000,
                   modified=400000100):
    name_bytes = name.encode("mac_roman") if isinstance(name, str) else name
    header = bytearray(94)
    header[0] = len(name_bytes)
    header[1:64] = name_bytes.ljust(63, b"\0")
    header[64:68] = type
    header[68:72] = creator
    header[72] = (flags >> 8) & 0xFF
    struct.pack_into(">H", header, 74, 1 if locked else 0)
    struct.pack_into(">II", header, 76, data_len, rsrc_len)
    struct.pack_into(">II", header, 84, created, modified)
    # Header CRC polynomial is not established by the format notes;
    # the field exists, we write a fixed value.
    struct.pack_into(">H", header, 92, 0x1234)
    return bytes(header)


def packit(files=((b"TestFile", b"hello world", b"", b"TEXT", b"TTxt"),),
           kind="stored", tail_word=True):
    """Build a .pit image. ``files`` items are
    (name, data, rsrc, type, creator) tuples or full dicts.
    ``kind`` is 'stored', 'huffman' or 'encrypted'."""
    out = bytearray()
    for spec in files:
        if isinstance(spec, dict):
            name = spec.get("name", b"TestFile")
            data = spec.get("data", b"")
            rsrc = spec.get("rsrc", b"")
            type_ = spec.get("type", b"TEXT")
            creator = spec.get("creator", b"TTxt")
            flags = spec.get("flags", 0x0100)
            locked = spec.get("locked", False)
            created = spec.get("created", 400000000)
            modified = spec.get("modified", 400000100)
            spec_kind = spec.get("kind", kind)
        else:
            name, data, rsrc, type_, creator = spec
            flags, locked, created, modified, spec_kind = 0x0100, False, 400000000, 400000100, kind
        header = _packit_header(name, len(data), len(rsrc), type_, creator,
                                flags, locked, created, modified)
        stream = header + data + rsrc + b"\xde\xad"
        if spec_kind == "stored":
            out += b"PMag" + stream
        elif spec_kind == "huffman":
            out += b"PMa4" + huffman_encode(stream)
        elif spec_kind == "encrypted":
            out += b"PMa5" + stream
        else:
            raise ValueError("unknown kind %r" % spec_kind)
    if tail_word:
        out += b"PEnd"
    return bytes(out)


class LsbBitWriter:
    def __init__(self):
        self.bitbuf = 0
        self.nbits = 0
        self.out = bytearray()

    def put(self, code, size):
        self.bitbuf |= code << self.nbits
        self.nbits += size
        while self.nbits >= 8:
            self.out.append(self.bitbuf & 0xFF)
            self.bitbuf >>= 8
            self.nbits -= 8

    def flush(self):
        if self.nbits:
            self.out.append(self.bitbuf & 0xFF)
            self.bitbuf = 0
            self.nbits = 0
        return bytes(self.out)


def lzw_compress(data, maxbits=13, blockmode=True):
    """compress(1)-compatible encoder. Mirrors the decoder's table-add
    schedule exactly: the first emitted code adds no entry (the decoder
    has no previous string for it); every later code adds
    prev_string + first byte of the current string, so the width bumps
    land on the same code position on both sides. No clear codes are
    emitted; the table never fills for test-sized inputs."""
    table = {bytes([i]): i for i in range(256)}
    next_code = 257 if blockmode else 256
    symbolsize = 9
    maxsymbols = 1 << maxbits
    writer = LsbBitWriter()

    def add(entry):
        nonlocal next_code, symbolsize
        if next_code < maxsymbols:
            table[entry] = next_code
            next_code += 1
            if next_code < maxsymbols and (next_code & (next_code - 1)) == 0:
                symbolsize += 1

    w = b""
    prev_w = None
    for byte in data:
        wc = w + bytes([byte])
        if wc in table:
            w = wc
            continue
        writer.put(table[w], symbolsize)
        if prev_w is not None:
            add(prev_w + w[:1])
        prev_w = w
        w = bytes([byte])
    if w:
        writer.put(table[w], symbolsize)
        if prev_w is not None:
            add(prev_w + w[:1])
    return writer.flush()


def _sqp_record(name, data_len, rsrc_len, data_clen, rsrc_clen, data_off,
                rsrc_off, type=b"TEXT", creator=b"TTxt", flags16=0x0100,
                created=400000000, modified=400000100, stored_data=False,
                stored_rsrc=False):
    name_bytes = name.encode("mac_roman") if isinstance(name, str) else name
    rec = bytearray(86)
    struct.pack_into(">II", rec, 4, rsrc_clen, data_clen)
    struct.pack_into(">II", rec, 12, data_off, rsrc_off)
    rec[20:24] = type
    rec[24:28] = creator
    struct.pack_into(">H", rec, 28, flags16)
    rec[36] = len(name_bytes)
    rec[37:37 + 31] = name_bytes.ljust(31, b"\0")
    struct.pack_into(">II", rec, 68, created, modified)
    struct.pack_into(">II", rec, 76, rsrc_len, data_len)
    flags = 0
    if stored_data:
        flags |= 0x02
    if stored_rsrc:
        flags |= 0x04
    rec[84] = flags
    return bytes(rec)


def sqp(entries, version=1):
    """Build an AppleLink .pkg. ``entries`` is a list of dicts:
    name, data, rsrc, type, creator, flags16, locked, created, modified,
    folder, level, stored (bool: store both forks uncompressed)."""
    member_bytes = bytearray()
    placed = []
    cursor = None  # absolute offset where member bytes begin (patched later)
    for entry in entries:
        if entry.get("folder"):
            placed.append((entry, None, None))
            continue
        data = entry.get("data", b"")
        rsrc = entry.get("rsrc", b"")
        stored = entry.get("stored", False)
        if stored:
            dcomp, rcomp = data, rsrc
        else:
            dcomp, rcomp = lzw_compress(data), lzw_compress(rsrc)
        placed.append((entry, len(member_bytes), len(member_bytes) + len(dcomp)))
        member_bytes += dcomp + rcomp
    if version == 0:
        sqp_count = len(placed)
        base = 10 + 86 * sqp_count
        hfs_header = b""
    else:
        sqp_count = len(placed)
        base = 10 + 86 * sqp_count
        hfs_header = struct.pack(">I", len(placed)) + b"\0" * 8
        base = 10 + 86 * sqp_count + 12 + 90 * len(placed)
    member_base = base
    records = []
    hfs_records = []
    for entry, data_rel, rsrc_rel in placed:
        if entry.get("folder"):
            name = entry.get("name", b"Folder")
            level = entry.get("level", 1)
            rec = _sqp_record(name, 0, 0, 0, 0, 0, 0,
                              type=b"HBSF", creator=b"MACS",
                              flags16=entry.get("flags16", 0),
                              created=entry.get("created", 400000000),
                              modified=entry.get("modified", 400000100))
            records.append(b"\0" * 86)
            hfs_records.append(struct.pack(">HH", level, 1) + rec)
            continue
        data = entry.get("data", b"")
        rsrc = entry.get("rsrc", b"")
        stored = entry.get("stored", False)
        if stored:
            dcomp, rcomp = data, rsrc
        else:
            dcomp, rcomp = lzw_compress(data), lzw_compress(rsrc)
        doff = member_base + data_rel
        roff = member_base + rsrc_rel
        level = entry.get("level", 1)
        rec = _sqp_record(entry.get("name", b"File"), len(data), len(rsrc),
                          len(dcomp), len(rcomp), doff, roff,
                          type=entry.get("type", b"TEXT"),
                          creator=entry.get("creator", b"TTxt"),
                          flags16=entry.get("flags16", 0x0100),
                          created=entry.get("created", 400000000),
                          modified=entry.get("modified", 400000100),
                          stored_data=stored, stored_rsrc=stored)
        records.append(rec)
        hfs_records.append(struct.pack(">HH", level, 0) + rec)
    out = bytearray()
    out += bytes([sqp_count, version]) + b"\0" * 8
    for rec in records:
        out += rec
    if version == 1:
        out += hfs_header
        for rec in hfs_records:
            out += rec
    out += member_bytes
    return bytes(out)


def rle90_encode(payload):
    """RLE-90 (StuffIt method 1): a run of three or more becomes a
    leading literal plus ``0x90`` and a count byte N (the decoder then
    emits N bytes in total for the group); ``0x90`` itself is always
    written ``0x90 0x00``; ``0x90 0x01`` never appears.  Test-side
    counterpart of ``macextract._rle90.rle90_decode``."""
    out = bytearray()
    index = 0
    size = len(payload)
    while index < size:
        byte = payload[index]
        run = 1
        while (index + run < size and payload[index + run] == byte
               and run < 255):
            run += 1
        if run >= 3:
            out += b"\x90\x00" if byte == 0x90 else bytes([byte])
            out.append(0x90)
            out.append(run)      # group emits 1 + (run - 1) more = run
            index += run
        else:
            out += b"\x90\x00" if byte == 0x90 else bytes([byte])
            index += 1
    return bytes(out)


def _sit13_put_meta(writer, value):
    writer.put(_sit13.META_CODES[value], _sit13.META_LENGTHS[value])


def _sit13_put_lengths(writer, lengths):
    for length in lengths:
        _sit13_put_meta(writer, length - 1 if length else 31)


def _sit13_put_symbol(writer, codes, symbol):
    length, value = codes[symbol]
    for bit in range(length - 1, -1, -1):   # MSB of the code leaves first
        writer.put((value >> bit) & 1, 1)


def _sit13_tokens(payload):
    """Greedy LZ over a 64 KB window, matches of 3..64 bytes.  Candidate
    starts come from an index of three-byte prefixes, so the scan costs
    the candidates rather than the whole window."""
    size = len(payload)
    index = {}
    for at in range(max(0, size - 2)):
        index.setdefault(payload[at:at + 3], []).append(at)
    tokens = []
    pos = 0
    while pos < size:
        best_len = 0
        best_dist = 0
        limit = min(64, size - pos)
        floor = max(0, pos - 65536)
        if limit >= 3:
            for start in reversed(index.get(payload[pos:pos + 3], ())):
                if start >= pos:
                    continue
                if start < floor:
                    break
                length = 0
                while (length < limit
                       and payload[start + length] == payload[pos + length]):
                    length += 1
                if length > best_len:
                    best_len = length
                    best_dist = pos - start
                    if best_len == limit:
                        break
        if best_len >= 3:
            tokens.append(("match", best_len, best_dist))
            pos += best_len
        else:
            tokens.append(("lit", payload[pos]))
            pos += 1
    return tokens


def sit13_encode(payload, selector=None, f_bit=False, end_marker=False):
    """Counterpart of ``macextract._sit13.sit13_decode``.  ``selector``
    None writes dynamic tables through the meta code (``f_bit`` says the
    second literal/length code repeats the first and is then not
    written); ``selector`` 1..5 uses a predefined set instead.
    ``end_marker`` emits the 320 end symbol first, which a decoder must
    refuse while the fork's length is unfinished."""
    writer = LsbBitWriter()
    tokens = _sit13_tokens(payload)

    if selector is None:
        first_lengths = [9] * 321
        second_lengths = [9] * 321
        offset_lengths = [5] * 17
        writer.put((0x08 if f_bit else 0) | 7, 8)
        _sit13_put_lengths(writer, first_lengths)
        if not f_bit:
            _sit13_put_lengths(writer, second_lengths)
        _sit13_put_lengths(writer, offset_lengths)
        first_codes = _sit13.canonical_codes(first_lengths)
        second_codes = (first_codes if f_bit
                        else _sit13.canonical_codes(second_lengths))
        offset_codes = _sit13.canonical_codes(offset_lengths)
    else:
        writer.put(selector << 4, 8)
        first_codes = _sit13.canonical_codes(_sit13.FIRST_LENGTHS[selector - 1])
        second_codes = _sit13.canonical_codes(_sit13.SECOND_LENGTHS[selector - 1])
        offset_codes = _sit13.canonical_codes(_sit13.OFFSET_LENGTHS[selector - 1])

    if end_marker:
        _sit13_put_symbol(writer, first_codes, 320)
        return writer.flush()

    current = first_codes
    for token in tokens:
        if token[0] == "lit":
            _sit13_put_symbol(writer, current, token[1])
            current = first_codes
            continue
        _, length, distance = token
        _sit13_put_symbol(writer, current, 253 + length)
        current = second_codes
        low = distance - 1
        bits = 0 if low == 0 else low.bit_length()
        _sit13_put_symbol(writer, offset_codes, bits)
        if bits >= 2:
            writer.put(low - (1 << (bits - 1)), bits - 1)
    return writer.flush()


def _sit_compress(method, payload, spec):
    if not payload:
        return b""
    if method == 0:
        return payload
    if method == 1:
        return rle90_encode(payload)
    if method == 2:
        return lzw_compress(payload, maxbits=14, blockmode=True)
    if method == 3:
        return huffman_encode(payload)
    if method == 13:
        return sit13_encode(payload, selector=spec.get("selector"),
                            f_bit=spec.get("f_bit", False))
    if method == 15:
        return arsenic_encode(payload,
                              blockbits=spec.get("arsenic_blockbits", 9),
                              randomized=spec.get("arsenic_randomized", False))
    raise ValueError("stuffit: no encoder for method %d" % method)


def _sit_folder_header(name, marker):
    if isinstance(name, str):
        name = name.encode("mac_roman")
    name = name[:31]
    hdr = bytearray(112)
    hdr[0] = marker
    hdr[1] = marker
    hdr[2] = len(name)
    hdr[3:34] = name.ljust(31, b"\0")
    struct.pack_into(">H", hdr, 34, crc16_arc(bytes(hdr[2:34])))
    struct.pack_into(">I", hdr, 62, 0xFFFFFFFF)
    struct.pack_into(">H", hdr, 110, crc16_arc(bytes(hdr[:110])))
    return bytes(hdr)


def _sit_file_header(spec, rsrc, data, rsrc_stored, data_stored):
    name = spec.get("name", b"TestFile")
    if isinstance(name, str):
        name = name.encode("mac_roman")
    name = name[:31]
    method = spec.get("method", 0)
    rsrc_method = spec.get("rsrc_method", 0)
    encrypt_bit = spec.get("encrypt_bit", 0)
    dmeth = method | encrypt_bit
    rmeth = rsrc_method | encrypt_bit
    if spec.get("optimizer") is not None:
        dmeth |= 0x40
    if spec.get("rsrc_optimizer") is not None:
        rmeth |= 0x40

    hdr = bytearray(112)
    hdr[0] = rmeth
    hdr[1] = dmeth
    hdr[2] = len(name)
    hdr[3:34] = name.ljust(31, b"\0")
    struct.pack_into(">H", hdr, 34, crc16_arc(bytes(hdr[2:34])))
    if spec.get("bad_name_crc"):
        hdr[34] ^= 0xFF
    struct.pack_into(">H", hdr, 36, 0x8000 if spec.get("locked") else 0)
    struct.pack_into(">I", hdr, 62, 0xFFFFFFFF)
    hdr[66:70] = spec.get("type", b"TEXT")
    hdr[70:74] = spec.get("creator", b"TTxt")
    struct.pack_into(">H", hdr, 74, spec.get("finder_flags", 0x0100))
    struct.pack_into(">I", hdr, 76, spec.get("created", 400000000))
    struct.pack_into(">I", hdr, 80, spec.get("modified", 400000100))
    struct.pack_into(">II", hdr, 84, len(rsrc), len(data))
    struct.pack_into(">II", hdr, 92, len(rsrc_stored), len(data_stored))
    struct.pack_into(">H", hdr, 100, crc16_arc(rsrc))
    struct.pack_into(">H", hdr, 102, crc16_arc(data))
    if spec.get("bad_data_crc"):
        hdr[102] ^= 0xFF
    if spec.get("bad_rsrc_crc"):
        hdr[100] ^= 0xFF
    if spec.get("optimizer") is not None:
        hdr[106] = spec["optimizer"]
    if spec.get("data_encrypt_id") is not None:
        hdr[107] = spec["data_encrypt_id"]
    if spec.get("rsrc_optimizer") is not None:
        hdr[108] = spec["rsrc_optimizer"]
    if spec.get("rsrc_encrypt_id") is not None:
        hdr[109] = spec["rsrc_encrypt_id"]
    struct.pack_into(">H", hdr, 110, crc16_arc(bytes(hdr[:110])))
    if spec.get("bad_header_crc"):
        hdr[110] ^= 0xFFFF
    return bytes(hdr)


def stuffit(files=(), version=1, magic=b"SIT!", totalsize=None):
    """Build a StuffIt classic image.  ``files`` items are dicts (or
    ``(name, data)`` tuples); a dict with ``folder`` starts a folder,
    a dict with ``folder_end`` closes one.  File keys: name, data,
    rsrc, method, rsrc_method (0 stored, 1 RLE-90, 2 LZW-14, 3
    Huffman, 13 LZ+Huffman), selector/f_bit (method 13), locked,
    type, creator, finder_flags, created, modified, encrypt_bit (0x80
    or 0x10), optimizer / rsrc_optimizer (id), and the bad_* booleans
    that flip a stored CRC."""
    records = []
    bodies = []
    count = 0
    for spec in files:
        if isinstance(spec, tuple):
            spec = {"name": spec[0], "data": spec[1]}
        if "folder" in spec:
            records.append(_sit_folder_header(spec["folder"], 0x20))
            bodies.append(b"")
            continue
        if spec.get("folder_end"):
            records.append(_sit_folder_header(spec.get("name", b""), 0x21))
            bodies.append(b"")
            continue
        data = spec.get("data", b"")
        rsrc = spec.get("rsrc", b"")
        data_stored = _sit_compress(spec.get("method", 0), data, spec)
        rsrc_stored = _sit_compress(spec.get("rsrc_method", 0), rsrc, spec)
        records.append(_sit_file_header(spec, rsrc, data,
                                        rsrc_stored, data_stored))
        bodies.append(rsrc_stored + data_stored)
        count += 1

    header = bytearray(22)
    header[0:4] = magic.ljust(4, b"\0")[:4]
    struct.pack_into(">H", header, 4, count)
    header[10:14] = b"rLau"
    header[14] = version
    # Each header is followed immediately by its fork bytes.
    body = b"".join(rec + fork for rec, fork in zip(records, bodies))
    size = len(header) + len(body) if totalsize is None else totalsize
    struct.pack_into(">I", header, 6, size)
    return bytes(header) + body


# --- StuffIt 5 ---------------------------------------------------------

SIT5_BANNER = (b"StuffIt (c)1997-2024 Aladdin Systems, Inc., "
               b"http://www.aladdinsys.com/StuffIt/\r\n")


def _s5_md5_5(data):
    return hashlib.md5(data, usedforsecurity=False).digest()[:5]


def _s5_pw_bytes(password):
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)


def _s5_name(name):
    if isinstance(name, str):
        return name.encode("utf-8")
    return bytes(name)


def _sit5_compress(method, payload, spec):
    if method in (0, 1, 2, 3, 13, 15):
        return _sit_compress(method, payload, spec)
    # No encoder for the rest: the bytes stand as stored and the method
    # byte says what they are, which the reader must refuse by name.
    return payload


def _sit5_second_block(entry_version, has_rsrc, rsrcfields, rsrc_key,
                       type_, creator, finder_flags):
    """The block after the comment: flags, its own CRC-16/ARC gate
    (entry version 1 only), then the Finder info.  With a resource
    fork, the 14 fork-field bytes and the fork's key bytes are inside
    that CRC too."""
    block = bytearray(36 if entry_version == 1 else 32)
    struct.pack_into(">H", block, 0, 1 if has_rsrc else 0)
    block[4:8] = type_
    block[8:12] = creator
    struct.pack_into(">H", block, 12, finder_flags)
    if entry_version == 1:
        covered = bytes(block)
        if has_rsrc:
            covered += rsrcfields
        if rsrc_key:
            covered += rsrc_key
        struct.pack_into(">H", block, 2, crc16_arc(covered))
    return bytes(block)


def _sit5_header(entry_version, eflags, diroffs, name, sizes, mid,
                 comment, comment_space, block, extras=b""):
    """One entry header: 46 fixed bytes, then the fork-count or method
    bytes, the name, the comment (only when the header size leaves
    room), the second block and any resource-fork fields.  With
    ``comment_space`` False the header size stops at the name — the
    comment gate sees no room — but the block still follows in the
    bytes.  The header CRC at 32 stays 0 here; ``stuffit5`` fills it
    once every offset is known."""
    tail = mid + name
    headersize = 46 + len(tail)
    if comment_space:
        text = comment or b""
        tail += struct.pack(">HH", len(text), 0) + text
    tail += block + extras
    if comment_space:
        headersize = 46 + len(tail)
    fixed = bytearray(46)
    struct.pack_into(">I", fixed, 0, 0xA5A5A5A5)
    fixed[4] = entry_version
    struct.pack_into(">H", fixed, 6, headersize)
    fixed[9] = eflags
    struct.pack_into(">I", fixed, 10, 400000000)
    struct.pack_into(">I", fixed, 14, 400000100)
    struct.pack_into(">I", fixed, 26, diroffs)
    struct.pack_into(">H", fixed, 30, len(name))
    fixed[34:46] = sizes
    return bytes(fixed) + tail


def stuffit5(files=(), password=None, blocks14=False, comment_block=False,
             archive_comment=b"", style=b"", entry_version=1,
             comment_space=True, marker=True, marker_headersize=None,
             hash_len=None, count=None, firstoffs=None, totalsize=None,
             bad_id=False):
    """Build a StuffIt 5 image.  ``files`` items are dicts (or
    ``(name, data)`` tuples); a dict with ``folder`` opens a folder,
    a dict with ``folder_end`` closes one — every folder is followed by
    the format's marker entry.  File keys: name, data, rsrc (its
    presence sets the resource-fork flag), method, rsrc_method,
    selector/f_bit (method 13), encrypted, data_key / rsrc_key (five
    bytes), data_passlen / rsrc_passlen (override, to misstate the
    key length), comment, entry_version, datacomp_extra, type,
    creator, finder_flags, and bad_data_crc / bad_rsrc_crc /
    bad_block_crc.  Archive keys: password (adds the flag-0x80 hash),
    blocks14, comment_block, archive_comment, style, entry_version,
    comment_space, marker, marker_headersize, hash_len, count,
    firstoffs, totalsize, bad_id."""
    if archive_comment:
        comment_block = True
    arch_flags = ((0x80 if password is not None else 0)
                  | (0x10 if blocks14 else 0)
                  | (0x20 if comment_block else 0))

    out = bytearray(100)
    out[0:80] = SIT5_BANNER
    out[82] = 5
    out[83] = arch_flags
    if blocks14:
        out += b"\0" * 14
    if comment_block:
        out += struct.pack(">HH", len(archive_comment), len(style))
    if password is not None:
        key5 = _s5_md5_5(_s5_pw_bytes(password))
        stored_hash = _s5_md5_5(key5) + b"\0" * 16
        out += bytes([5 if hash_len is None else hash_len]) + stored_hash
    out += archive_comment + style
    first = len(out)

    pos_list = []
    dir_slots = {}
    dir_children = {}
    stack = []
    root_count = 0

    for spec in files:
        if isinstance(spec, tuple):
            spec = {"name": spec[0], "data": spec[1]}
        diroffs = stack[-1] if stack else 0

        if "folder" in spec:
            if stack:
                dir_children[stack[-1]] += 1
            else:
                root_count += 1
            name = _s5_name(spec["folder"])
            ev = spec.get("entry_version", entry_version)
            block = _sit5_second_block(
                ev, False, b"", None, spec.get("type", b"TEXT"),
                spec.get("creator", b"TTxt"), spec.get("finder_flags", 0x0100))
            pos = len(out)
            pos_list.append(pos)
            out += _sit5_header(
                ev, 0x40, diroffs, name, b"\0" * 12,
                struct.pack(">H", 0), spec.get("comment"), comment_space, block)
            dir_slots[pos] = pos + 46
            dir_children[pos] = 0
            if marker:
                pos_list.append(len(out))
                marker_bytes = _sit5_header(
                    1, 0x40, 0, b"", b"\xff\xff\xff\xff" + b"\0" * 8,
                    b"\0\0", None, False, b"")
                if marker_headersize is not None:
                    marker_bytes = (marker_bytes[:6]
                                    + struct.pack(">H", marker_headersize)
                                    + marker_bytes[8:])
                out += marker_bytes
            stack.append(pos)
            continue

        if spec.get("folder_end"):
            if stack:
                stack.pop()
            continue

        if stack:
            dir_children[stack[-1]] += 1
        else:
            root_count += 1

        name = _s5_name(spec.get("name", b"File"))
        data = spec.get("data", b"")
        has_rsrc = "rsrc" in spec
        rsrc = spec.get("rsrc", b"")
        ev = spec.get("entry_version", entry_version)
        encrypted = bool(spec.get("encrypted"))
        eflags = 0x20 if encrypted else 0
        dmethod = spec.get("method", 0)
        rmethod = spec.get("rsrc_method", 0)
        dstored = _sit5_compress(dmethod, data, spec)
        rstored = _sit5_compress(rmethod, rsrc, spec) if has_rsrc else b""
        dkey = _s5_name(spec.get("data_key", b"DATKY"))
        rkey = _s5_name(spec.get("rsrc_key", b"RSRKY"))

        dpass = spec.get("data_passlen")
        if dpass is None:
            dpass = 5 if (encrypted and data) else 0
        rpass = spec.get("rsrc_passlen")
        if rpass is None:
            rpass = 5 if (encrypted and rsrc) else 0

        if encrypted and password is not None:
            akey = _s5_md5_5(_s5_pw_bytes(password))
            if data:
                dstored = rc4(dstored, akey + dkey)
            if rsrc:
                rstored = rc4(rstored, akey + rkey)

        # The wiki: a fork compressed with method 15 stores zero in
        # its CRC-16 field — the stream checks itself.
        datacrc = 0 if dmethod == 15 else crc16_arc(data)
        rsrccrc = 0 if rmethod == 15 else crc16_arc(rsrc)
        if spec.get("bad_data_crc"):
            datacrc ^= 0xFFFF
        if spec.get("bad_rsrc_crc"):
            rsrccrc ^= 0xFFFF

        sizes = struct.pack(
            ">IIH", len(data), len(dstored) + spec.get("datacomp_extra", 0),
            datacrc) + b"\0\0"
        mid = bytes([dmethod, dpass]) + ((dkey * 4)[:dpass] if dpass else b"")

        rsrcfields = b""
        rsrc_key_crc = None
        if has_rsrc:
            rsrcfields = struct.pack(
                ">IIHHBB", len(rsrc), len(rstored), rsrccrc, 0,
                rmethod, rpass)
            if rpass:
                rsrc_key_crc = (rkey * 4)[:rpass]
        block = _sit5_second_block(
            ev, has_rsrc, rsrcfields, rsrc_key_crc,
            spec.get("type", b"TEXT"), spec.get("creator", b"TTxt"),
            spec.get("finder_flags", 0x0100))
        if spec.get("bad_block_crc"):
            block = block[:2] + bytes([block[2] ^ 0xFF]) + block[3:]
        extras = b""
        if has_rsrc:
            extras = rsrcfields + ((rkey * 4)[:rpass] if rpass else b"")

        pos = len(out)
        pos_list.append(pos)
        out += _sit5_header(ev, eflags, diroffs, name, sizes, mid,
                            spec.get("comment"), comment_space, block, extras)
        out += rstored + dstored

    # Offsets are only known now: child counts, the prev/next chain,
    # then every entry header's CRC over its own header size with the
    # CRC field zeroed.
    for p, slot in dir_slots.items():
        struct.pack_into(">H", out, slot, dir_children[p])
    for i, p in enumerate(pos_list):
        struct.pack_into(">I", out, p + 18, pos_list[i - 1] if i else 0)
        struct.pack_into(">I", out, p + 22,
                         pos_list[i + 1] if i + 1 < len(pos_list) else 0)
    for p in pos_list:
        size = struct.unpack_from(">H", out, p + 6)[0]
        out[p + 32] = out[p + 33] = 0
        if size and p + size <= len(out):
            struct.pack_into(">H", out, p + 32,
                             crc16_arc(bytes(out[p:p + size])))

    struct.pack_into(">I", out, 84,
                     len(out) if totalsize is None else totalsize)
    struct.pack_into(">H", out, 92,
                     root_count if count is None else count)
    struct.pack_into(">I", out, 94, first if firstoffs is None else firstoffs)
    first = struct.unpack_from(">I", out, 94)[0]
    if bad_id and first + 4 <= len(out):
        out[first:first + 4] = b"\0\0\0\0"
    return bytes(out)


# --- StuffIt method 15, Arsenic --------------------------------------

def _ars_rle_tokens(payload):
    """The spec's byte-stuffing RLE, cut into tokens the block packer
    must never split: a run of 4..255 becomes four copies plus a count
    byte (the run length minus four), runs longer than 255 become a
    run of 255 and the rest, shorter runs stay literal bytes."""
    tokens = []
    i = 0
    n = len(payload)
    while i < n:
        j = i
        while j < n and payload[j] == payload[i] and j - i < 255:
            j += 1
        run = j - i
        if run >= 4:
            tokens.append(bytes([payload[i]]) * 4 + bytes([run - 4]))
        else:
            tokens.extend(bytes([b]) for b in payload[i:j])
        i = j
    return tokens


def _ars_pack_blocks(tokens, blocksize):
    blocks = []
    current = []
    size = 0
    for token in tokens:
        if size + len(token) > blocksize:
            blocks.append(b"".join(current))
            current = []
            size = 0
        current.append(token)
        size += len(token)
    if current:
        blocks.append(b"".join(current))
    return blocks


def _ars_randomize(data):
    rndindex = 0
    pos = RNDTABLE[0]
    n = len(data)
    while pos < n:
        data[pos] ^= 1
        rndindex = (rndindex + 1) & 0xFF
        pos += RNDTABLE[rndindex]


def _ars_forward_bwt(block):
    """The wrapping BWT: sort the rotations (stable, so equal ones stay
    in start-index order), take the preceding byte as the L column and
    the original rotation's rank as the primary index."""
    n = len(block)
    order = sorted(range(n), key=lambda s: block[s:] + block[:s])
    lcolumn = bytes(block[(s - 1) % n] for s in order)
    primary = order.index(0)
    return lcolumn, primary


def _ars_mtf_encode(data):
    table = list(range(256))
    ranks = []
    for byte in data:
        rank = table.index(byte)
        ranks.append(rank)
        if rank:
            del table[rank]
            table.insert(0, byte)
    return ranks


def _ars_events(ranks):
    """MTF ranks as the selector stream the decoder eats: zero runs
    through the zero counter (selectors 0/1, k selectors for a run of
    Z = 2^k - 1 + B, B in k bits, LSB first), rank 1 as selector 2,
    larger ranks through the model their size names, block end 10."""
    events = []
    i = 0
    n = len(ranks)
    while i < n:
        if ranks[i] == 0:
            j = i
            while j < n and ranks[j] == 0:
                j += 1
            run = j - i
            k = (run + 1).bit_length() - 1
            bits = run - ((1 << k) - 1)
            for bit in range(k):
                events.append(("sel", (bits >> bit) & 1))
            i = j
            continue
        rank = ranks[i]
        if rank == 1:
            events.append(("sel", 2))
        else:
            selector = 1 + rank.bit_length()
            events.append(("sel", selector))
            events.append(("mtf", selector - 3, rank))
        i += 1
    events.append(("sel", 10))
    return events


class _ArsEncoder:
    """The quotient coder's encoder half: a window [xlo, xhi) over the
    integer the stream's bits form, with the decoder's own arithmetic
    around it.  The window is always non-empty — every step recentres
    the code by renorm*low, so the chosen symbol's band always lies
    inside the current one."""

    def __init__(self):
        self.range = ONE
        self.xlo = 0
        self.xhi = 1 << 26
        self.c = 0
        self.m = 26

    def symbol(self, model, value):
        index = value - model.first
        total = model.total
        renorm = self.range // total
        cum = sum(model.freq[:index])
        size = model.freq[index]
        if index == model.nsyms - 1:
            lo, hi = renorm * cum, self.range
        else:
            lo, hi = renorm * cum, renorm * (cum + size)
        lo += self.c
        hi += self.c
        if lo > self.xlo:
            self.xlo = lo
        if hi < self.xhi:
            self.xhi = hi
        if self.xlo >= self.xhi:
            raise AssertionError("arsenic encoder: empty window")
        lowincr = renorm * cum
        if cum + size == total:
            range2 = self.range - lowincr
        else:
            range2 = renorm * size
        shifts = 0
        while range2 <= HALF:
            range2 <<= 1
            shifts += 1
        self.xlo <<= shifts
        self.xhi <<= shifts
        self.c = (self.c + lowincr) << shifts
        self.range = range2
        self.m += shifts
        model.bump(index)

    def bits(self, model, value, count):
        for i in range(count):
            self.symbol(model, (value >> i) & 1)


def arsenic_encode(payload, blockbits=9, randomized=False):
    """A complete Arsenic (method 15) stream for ``payload``.

    ``blockbits`` is the four-bit size code plus nine (9 = 512-byte
    blocks, the smallest legal); ``randomized`` sets every block's
    randomisation bit.  The RLE runs whole-file first, then blocks are
    cut at token boundaries — never between a run's four equal bytes
    and their count byte, which is where the references' per-block RLE
    state would misread them.
    """
    if not payload:
        raise ValueError("arsenic_encode: empty payload")
    blocksize = 1 << blockbits
    blocks = _ars_pack_blocks(_ars_rle_tokens(payload), blocksize)
    if not blocks:
        raise ValueError("arsenic_encode: nothing to encode")

    enc = _ArsEncoder()
    initial = Model(*MODELS[0])
    selector = Model(*MODELS[1])
    mtfmodels = [Model(*spec) for spec in MODELS[2:]]

    enc.bits(initial, ord("A"), 8)
    enc.bits(initial, ord("s"), 8)
    enc.bits(initial, blockbits - 9, 4)
    enc.symbol(initial, 0)              # first end-of-file bit: no
    for index, block in enumerate(blocks):
        data = bytearray(block)
        if randomized:
            _ars_randomize(data)
        lcolumn, primary = _ars_forward_bwt(bytes(data))
        enc.symbol(initial, 1 if randomized else 0)
        enc.bits(initial, primary, blockbits)
        for event in _ars_events(_ars_mtf_encode(lcolumn)):
            if event[0] == "sel":
                enc.symbol(selector, event[1])
            else:
                enc.symbol(mtfmodels[event[1]], event[2])
        selector.reset()
        for model in mtfmodels:
            model.reset()
        last = index == len(blocks) - 1
        enc.symbol(initial, 1 if last else 0)
        if last:
            enc.bits(initial, zlib.crc32(payload) & 0xFFFFFFFF, 32)

    bits = format(enc.xlo, "0%db" % enc.m)
    out = bytearray()
    for at in range(0, enc.m, 8):
        out.append(int(bits[at:at + 8].ljust(8, "0"), 2))
    return bytes(out)


# --- Compact Pro (.cpt) ---------------------------------------------

class MsbBitWriter:
    """Most-significant-bit-first bits, padded to whole bytes."""

    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def bit(self, b):
        self.acc = (self.acc << 1) | (b & 1)
        self.n += 1
        if self.n == 8:
            self.out.append(self.acc)
            self.acc = 0
            self.n = 0

    def bits(self, value, count):
        for i in range(count - 1, -1, -1):
            self.bit((value >> i) & 1)

    def to_bytes(self):
        out = bytearray(self.out)
        if self.n:
            out.append(self.acc << (8 - self.n))
        return bytes(out)


def rle8182_encode(payload):
    """The Compact Pro run filter's encoder.

    Runs of anything but 0x81 become one literal plus ``0x81 0x82 n``
    escapes (n-1 further copies, n <= 255).  The escape byte itself
    is the hard case: an 0x81 is only ever a literal when it is
    flushed by the byte after it, so a run of 0x81s is emitted as
    itself and the byte that follows decides — ``0x82`` gets the
    ``0x81 0x82 0x00`` literal pair, anything else flushes the chain
    as literals.  A file ending in 0x81 relies on the decoder's
    ``remaining != 1`` arm.
    """
    out = bytearray()
    i = 0
    n = len(payload)
    while i < n:
        b = payload[i]
        if b != 0x81:
            j = i
            while j < n and payload[j] == b:
                j += 1
            rest = j - i - 1
            out.append(b)
            while rest > 254:
                out += b"\x81\x82\xff"
                rest -= 254
            if rest >= 2:
                out += b"\x81\x82" + bytes([rest + 1])
            elif rest == 1:
                out.append(b)
            i = j
        else:
            j = i
            while j < n and payload[j] == 0x81:
                j += 1
            out += b"\x81" * (j - i)
            i = j
            if i < n and payload[i] == 0x82:
                out += b"\x82\x00"     # the literal pair 0x81 0x82
                i += 1
    return bytes(out)


_CPT_LIT_LIST = bytes([128]) + b"\x88" * 128   # 256 literals, length 8
_CPT_LEN_LIST = bytes([32]) + b"\x66" * 32     # 64 lengths, length 6
_CPT_OFF_LIST = bytes([64]) + b"\x77" * 64     # 128 offsets, length 7


def cpt_lzh_encode(payload):
    """An LZH fork of ``payload``: literals only, in blocks of
    0x1fff0 cost units (65272 nine-bit symbols), with the flush rule
    between them — align, then skip three bytes if an odd number was
    consumed since the block's data began, else two."""
    if not payload:
        return b""
    out = bytearray()
    i = 0
    while i < len(payload):
        out += _CPT_LIT_LIST + _CPT_LEN_LIST + _CPT_OFF_LIST
        writer = MsbBitWriter()
        cost = 0
        while cost < 0x1FFF0 and i < len(payload):
            writer.bit(1)
            writer.bits(payload[i], 8)
            i += 1
            cost += 2
        data = writer.to_bytes()
        out += data
        if i < len(payload):
            out += b"\0\0" + (b"\0" if len(data) & 1 else b"")
    return bytes(out)


def cpt_fork(payload, lzh=False):
    """One fork's stored bytes.  The decoder runs LZH first and the
    run filter over its output, so the encoder goes the other way:
    RLE, then LZH over the RLE's stream."""
    if not payload:
        return b""
    stored = rle8182_encode(payload)
    if lzh:
        return cpt_lzh_encode(stored)
    return stored


def _cpt_encrypt(password, preamble, streams):
    """Encrypt an entry's stored forks in order, eight preamble bytes
    first, on one cipher."""
    from macextract.formats.cpt import _Cipher
    cipher = _Cipher(password)
    first = True
    out = []
    for stream in streams:
        if first:
            stream = preamble + stream
            first = False
        out.append(cipher.encrypt(stream))
    return out


def _cpt_count(nodes):
    total = 0
    for node in nodes:
        if "folder" in node:
            total += 1 + _cpt_count(node["children"])
        else:
            total += 1
    return total


def compactpro(files=(), comment=b"", xmagic=0, password=None):
    """A Compact Pro archive.

    ``files`` is a flat list: ``{"folder": "Dir"}`` opens a folder,
    ``{"folder_end": True}`` closes it, anything else is a file with
    ``name`` (str), ``data`` and/or ``rsrc`` bytes, optional ``lzh``
    (or per-fork ``rsrc_lzh`` / ``data_lzh``), ``type``, ``creator``,
    ``created``, ``modified``, ``finder_flags``, and ``encrypted``.
    """
    if len(comment) > 255:
        raise ValueError("compactpro: comment longer than 255 bytes")

    # The flat list becomes a tree so folder counts (every header
    # below, nested included) are exact.
    nodes = []
    stack = [nodes]
    for spec in files:
        if "folder" in spec:
            children = []
            stack[-1].append({"folder": spec["folder"], "children": children})
            stack.append(children)
        elif spec.get("folder_end"):
            if len(stack) == 1:
                raise ValueError("compactpro: folder_end with no folder")
            stack.pop()
        else:
            stack[-1].append(spec)
    if len(stack) != 1:
        raise ValueError("compactpro: unclosed folder")

    records = []

    def collect(some):
        for node in some:
            if "folder" in node:
                records.append(("dir", node["folder"],
                                _cpt_count(node["children"])))
                collect(node["children"])
            else:
                records.append(("file", node, None))

    collect(nodes)

    # Forks are laid out first, so every record knows its offset.
    bodies = []
    fork_at = 8
    entries = []
    for kind, node, count in records:
        if kind == "dir":
            entries.append((kind, node.encode("mac_roman"), count, None))
            continue
        rsrc = node.get("rsrc", b"")
        data = node.get("data", b"")
        r_lzh = node.get("rsrc_lzh", node.get("lzh", False))
        d_lzh = node.get("data_lzh", node.get("lzh", False))
        r_stored = cpt_fork(rsrc, r_lzh)
        d_stored = cpt_fork(data, d_lzh)
        flags = (1 if node.get("encrypted") else 0) \
            | (2 if r_lzh else 0) | (4 if d_lzh else 0)
        if flags & 1:
            if password is None:
                raise ValueError("compactpro: encrypted entry, no password")
            # The eight-byte preamble belongs to the first fork with
            # bytes, counted in its compressed length.
            streams = []
            if r_stored:
                streams.append(r_stored)
                streams.append(d_stored)
            elif d_stored:
                streams.append(d_stored)
            else:
                streams = []
            if streams:
                r_enc, d_enc = (None, None)
                enc = _cpt_encrypt(password, b"\0" * 8, streams)
                if r_stored:
                    r_enc, d_enc = enc
                else:
                    d_enc = enc[0]
                r_stored, d_stored = r_enc or b"", d_enc or b""
        filecrc = zlib.crc32(rsrc + data) ^ 0xFFFFFFFF
        fileoffs = fork_at
        fork_at += len(r_stored) + len(d_stored)
        bodies.append(r_stored + d_stored)
        meta = struct.pack(
            ">BIIIIIHIHIIII", 1, fileoffs,
            int.from_bytes(_four(node.get("type", b"????")), "big"),
            int.from_bytes(_four(node.get("creator", b"????")), "big"),
            node.get("created", 0), node.get("modified", 0),
            node.get("finder_flags", 0), filecrc, flags,
            len(rsrc), len(data), len(r_stored), len(d_stored))
        entries.append(("file", node.get("name", "").encode("mac_roman"),
                        meta, None))

    region = struct.pack(">H", len(entries)) + bytes([len(comment)]) + comment
    for kind, name, payload, _ in entries:
        nl = len(name) | (0x80 if kind == "dir" else 0)
        region += bytes([nl]) + name
        region += struct.pack(">H", payload) if kind == "dir" else payload
    index_off = 8 + sum(len(b) for b in bodies)
    index = struct.pack(">I", zlib.crc32(region) ^ 0xFFFFFFFF) + region
    header = bytes([1, 1]) + struct.pack(">H", xmagic) \
        + struct.pack(">I", index_off)
    return header + b"".join(bodies) + index


def _four(code):
    if isinstance(code, str):
        code = code.encode("ascii")
    return (code + b"????")[:4]


# ================================================================== #
# DiskDoubler fixtures                                               #
# ================================================================== #

def dd_delta_encode(payload):
    """Inverse of the running-sum transform: prefix-xor differences."""
    out = bytearray()
    prev = 0
    for byte in payload:
        out.append((byte - prev) & 0xFF)
        prev = byte
    return bytes(out)


def dd_sum16(payload, adj=0):
    return (sum(payload) + adj) & 0xFFFF


def dd_xsum(payload, even_complement=False):
    value = 0
    for byte in payload:
        value ^= byte
    if even_complement and (len(payload) & 1) == 0:
        value ^= 0xFF
    return value


def _contains(tree, node, target):
    if node >= 256:
        return node == target
    return (_contains(tree, tree.left[node], target)
            or _contains(tree, tree.right[node], target))


def dd_splay_encode(payload, ntrees=256):
    """Jones splay-tree codes, one tree per context, MSB-first, zero-padded
    to whole bytes.  Test-side counterpart of the method 2/5 decoders."""
    from macextract.formats.dd import _SplayTree
    if ntrees & (ntrees - 1):
        raise ValueError("ntrees must be a power of two")
    mask = ntrees - 1
    trees = [None] * ntrees
    writer = MsbBitWriter()
    ctx = 0
    for byte in payload:
        tree = trees[ctx]
        if tree is None:
            tree = _SplayTree()
            trees[ctx] = tree
        target = 256 + byte
        node = 1
        path = []
        while node < 256:
            if _contains(tree, tree.left[node], target):
                path.append(0)
                node = tree.left[node]
            else:
                path.append(1)
                node = tree.right[node]
        for bit in path:
            writer.bit(bit)
        tree.splay(target)
        ctx = byte & mask
    return writer.to_bytes()


def _dd_ad_block(compsize, uncompsize, flags):
    raw = compsize.to_bytes(2, "big") + uncompsize.to_bytes(2, "big")
    rest = b"\0" * 5 + bytes([flags]) + b"\0"   # 4 reserved + data xor, flags, byte 10
    head11 = raw + rest                            # 11 bytes
    check = 0
    for b in head11:
        check ^= b
    return head11 + bytes([check])


def dd_ad_encode(payload, stored=False):
    """Methods 6/9: one 12-byte-headed block per 1024 payload bytes,
    literal-only (or stored with stored=True).  Headers XOR to zero."""
    out = bytearray()
    pos = 0
    while pos < len(payload):
        chunk = payload[pos:pos + 1024]
        pos += len(chunk)
        uncomp = len(chunk)
        if stored:
            comp = chunk
            flags = 1
            out += _dd_ad_block(uncomp, uncomp, flags) + comp
            continue
        writer = MsbBitWriter()
        for b in chunk:
            writer.bit(0)
            writer.bits(b, 8)
        coded = writer.to_bytes()
        out += _dd_ad_block(len(coded), uncomp, 0) + coded
    return bytes(out)


def dd_stac_encode(payload):
    """Method 7: literal-only chunks, complemented MSB-first stream,
    18-byte header with an empty chunk table."""
    writer = MsbBitWriter()
    for b in payload:
        writer.bit(1)          # raw bit 1 -> dd_lzs(1) reads 0: a literal
        writer.bits(b, 8)      # decoder XORs 0xff back itself
    body = writer.to_bytes()
    return b"\0" * 6 + (0).to_bytes(4, "big") + b"\0" * 8 + body


def dd_ddn_encode(payload):
    """Method 10: a single literal-only block.  Raw literal stream
    (flags 0), one-symbol canonical codes (length 1) for offsets and
    lengths, all literal symbols code 0.  Bytes are the fork's
    decompressed bytes — apply dd_delta_encode first for the delta
    form."""
    numliterals = len(payload)
    uncompsize = numliterals
    head = (0 << 24) | (1 << 13) | (1 << 8) | (1 << 3)   # numcodes 1, numbytes 1, maxlength 1, numbits 1
    code_section = head.to_bytes(4, "big") + b"\x80"     # one length: 1 bit + pad

    offsetcompsize = len(code_section)                   # no offset symbols
    literalcompsize = numliterals                        # raw bytes
    length_bits = (numliterals + 7) // 8
    lengthcompsize = len(code_section) + length_bits

    length_data = b"\0" * length_bits

    header = bytearray()
    header += uncompsize.to_bytes(4, "big")
    header += numliterals.to_bytes(2, "big")
    header += (0).to_bytes(2, "big")                     # numoffsets
    header += lengthcompsize.to_bytes(2, "big")
    header += literalcompsize.to_bytes(2, "big")
    header += offsetcompsize.to_bytes(2, "big")
    header += b"\0"                                     # flags
    header += b"\0" * 6                                 # pad
    check = 0
    for b in header:
        check ^= b
    header.append(check)

    return bytes(header) + code_section + payload + code_section + length_data


def _dd_encode_fork(payload, method, delta=False, garble=False,
                    count=0, lzh=False):
    """One fork's stored bytes and stored checksum.

    ``payload`` is the DECOMPRESSED bytes.  ``delta`` applies the
    running-sum difference transform outside the coder.  ``garble``
    applies the 0x5a obfuscation to methods 1, 2 and 5 only.  Method 5
    writes a context-count byte (0 meaning 256).  Method 8 picks the
    RLE branch unless ``lzh`` is set.  Returns (fork_bytes, crc16);
    methods carrying per-block checks store 0."""
    p = dd_delta_encode(payload) if delta else payload
    xored = garble and method in (1, 2, 5)
    code_input = bytes(b ^ 0x5A for b in p) if xored else p
    if method == 0:
        fork = bytearray(p)
        crc = dd_sum16(p)
    elif method == 1:
        flags = 0x80 | 13
        header = b"\x1f\x9d" + bytes([flags])
        stored = bytes(b ^ 0x5A for b in header) if garble else header
        fork = bytearray(stored)
        fork += lzw_compress(code_input, maxbits=13, blockmode=True)
        crc = dd_sum16(p, 0x1F + 0x9D + flags)
    elif method == 2:
        fork = bytearray(dd_splay_encode(code_input, 256))
        crc = dd_sum16(p)
    elif method == 5:
        ntrees = 256 if count == 0 else count
        if ntrees & (ntrees - 1):
            ntrees = 1      # an invalid count is refused before the stream
        fork = bytearray([count])          # 0 means 256
        fork += dd_splay_encode(code_input, ntrees)
        crc = dd_sum16(p)
    elif method == 3:
        fork = bytearray(rle90_encode(p))
        crc = dd_sum16(p)
    elif method == 4:
        fork = bytearray(huffman_encode(p)) if p else bytearray()
        crc = dd_sum16(p)
    elif method in (6, 9):
        fork = bytearray(dd_ad_encode(p))
        crc = 0
    elif method == 7:
        fork = bytearray(dd_stac_encode(p))
        crc = dd_xsum(p, (len(p) & 1) == 0)
    elif method == 8:
        body = cpt_fork(p, lzh=lzh)
        prefix = b"\0" * 16 if lzh else b"\0" * 15 + b"\x01"
        fork = bytearray(prefix) + body
        crc = crc16_arc(p)
    elif method == 10:
        fork = bytearray(dd_ddn_encode(p))
        crc = 0
    else:
        raise ValueError("no fixture encoder for method %d" % method)
    return bytes(fork), crc


def _dd_header80(f):
    """The 80 bytes after the magic, from a field dict."""
    h = bytearray(80)
    struct.pack_into(">IIII", h, 0, f["datasize"], f["datacomp"],
                     f["rsrcsize"], f["rsrccomp"])
    h[16] = f["datamethod"] & 0xFF
    h[17] = f["rsrcmethod"] & 0xFF
    h[18] = f["info1"]
    struct.pack_into(">II", h, 20, f["modification"], f["creation"])
    h[28:32] = f["type"]
    h[32:36] = f["creator"]
    struct.pack_into(">H", h, 36, f["finderflags"])
    struct.pack_into(">H", h, 44, f["datacrc"] & 0xFFFF)
    struct.pack_into(">H", h, 46, f["rsrccrc"] & 0xFFFF)
    h[48] = f["info2"]
    struct.pack_into(">HH", h, 50, f["datadelta"], f["rsrcdelta"])
    return bytes(h)


def _dd_fields(data, rsrc, data_method, rsrc_method, delta, garble,
               lzh, count):
    """Encode both forks and return the field dict + payload bytes."""
    xdata, xrsrc = ((delta, delta) if isinstance(delta, bool) else delta)
    xored = garble and any(
        (m & 0x7F) in (1, 2, 5) for m in (data_method, rsrc_method))
    info1 = 0x2A if xored else 0x1F
    enc_d, crc_d = _dd_encode_fork(data, data_method & 0x7F,
                                   xdata and len(data) > 0, garble,
                                   count, lzh)
    enc_r, crc_r = _dd_encode_fork(rsrc, rsrc_method & 0x7F,
                                   xrsrc and len(rsrc) > 0, garble,
                                   count, lzh)
    f = {
        "datasize": len(data), "datacomp": len(enc_d),
        "rsrcsize": len(rsrc), "rsrccomp": len(enc_r),
        "datamethod": (data_method & 0x7F) | (0x80 if xdata and len(data) else 0),
        "rsrcmethod": (rsrc_method & 0x7F) | (0x80 if xrsrc and len(rsrc) else 0),
        "info1": info1, "info2": 0x00,
        "modification": 0xC9C00000, "creation": 0xC9C00000,
        "type": b"TEXT", "creator": b"TLst", "finderflags": 0,
        "datacrc": crc_d, "rsrccrc": crc_r,
        "datadelta": 1 if xdata and len(data) else 0,
        "rsrcdelta": 1 if xrsrc and len(rsrc) else 0,
    }
    return f, enc_d, enc_r


def dd_single(name=b"TestFile", data=b"hello world", rsrc=b"",
              data_method=0, rsrc_method=0, delta=False, garble=False,
              variant=84, trailer=True, count=0, lzh=False,
              type=b"TEXT", creator=b"TLst", flags=0):
    """A single DiskDoubler-compressed file (0xABCD0054, or 0xABCD0030
    for the 1990 48-byte header).  Returns the image bytes; the host
    filename supplies the entry's name minus a .dd suffix."""
    xored = garble and any(
        (m & 0x7F) in (1, 2, 5) for m in (data_method, rsrc_method))
    if variant == 48:
        f, enc_d, enc_r = _dd_fields(data, rsrc, data_method,
                                     rsrc_method, (False, False),
                                     False, lzh, count)
        f["datadelta"] = f["rsrcdelta"] = 0
        body = _dd_header80(f)[:44]
        image = bytearray(b"\xAB\xCD\x00\x30" + body)
        image += enc_d + enc_r
        return bytes(image)
    f, enc_d, enc_r = _dd_fields(data, rsrc, data_method, rsrc_method,
                                 delta, garble, lzh, count)
    f["type"] = type
    f["creator"] = creator
    f["finderflags"] = flags
    body = _dd_header80(f)
    head = b"\xAB\xCD\x00\x54" + body
    image = bytearray(head)
    image += enc_d + enc_r
    if trailer:
        image += head
    return bytes(image)


def _dd_ddar_record(name, *, isdir=0, enddir=0, span=0, rsrcsize=0,
                    created=0xC9C00000, modified=0xC9C00000,
                    type=b"DDAP", creator=b"DDAP", flags=0,
                    location=b"\0" * 4, datacrc=0, rsrccrc=0):
    rec = bytearray(124)
    rec[0:4] = b"DDAR"
    enc = name.encode("mac_roman")[:63] if isinstance(name, str) else name[:63]
    rec[8] = len(enc)
    rec[9:9 + len(enc)] = enc
    rec[72] = isdir
    rec[73] = enddir
    struct.pack_into(">II", rec, 74, span, rsrcsize)
    struct.pack_into(">II", rec, 82, created, modified)
    rec[90:94] = type
    rec[94:98] = creator
    struct.pack_into(">H", rec, 98, flags)
    rec[100:104] = location
    struct.pack_into(">HH", rec, 118, datacrc & 0xFFFF, rsrccrc & 0xFFFF)
    return bytes(rec)


def ddar(entries, trailer=True, created=0xC9C00000, modified=0xC9C00000):
    """A 'DDAR' archive.  ``entries`` is a list of dicts with keys
    ``path`` ('/'-separated), ``data``, ``rsrc``, and optionally
    ``type``, ``creator``, ``flags``, ``method``, ``rsrc_method``,
    ``delta``, ``garble``, ``raw``, ``count``, ``lzh``.  Folders are
    derived from the paths; entries order = record order."""
    out = bytearray(b"DDAR" + b"\0" * 74)
    open_dirs = []

    def folder_records(depth):
        while len(open_dirs) > depth:
            name = open_dirs.pop()
            out.extend(_dd_ddar_record(name, isdir=1, enddir=1,
                                       created=created,
                                       modified=modified))

    for entry in entries:
        parts = entry["path"].split("/")
        dirs, leaf = parts[:-1], parts[-1]
        for i, d in enumerate(dirs):
            if i < len(open_dirs) and open_dirs[i] == d:
                continue
            folder_records(i)
            open_dirs.append(d)
            out += _dd_ddar_record(d, isdir=1,
                                   created=created, modified=modified)
        folder_records(len(dirs))

        data = entry["data"]
        rsrc = entry.get("rsrc", b"")
        if entry.get("raw"):
            rec = _dd_ddar_record(
                leaf, span=len(data), rsrcsize=len(rsrc),
                created=created, modified=modified,
                type=entry.get("type", b"TEXT"),
                creator=entry.get("creator", b"TLst"),
                flags=entry.get("flags", 0),
                datacrc=dd_sum16(data), rsrccrc=dd_sum16(rsrc))
            out += rec + data + rsrc
            continue

        method = entry.get("method", 0)
        rmethod = entry.get("rsrc_method", method)
        delta = entry.get("delta", False)
        garble = entry.get("garble", False)
        f, enc_d, enc_r = _dd_fields(data, rsrc, method, rmethod,
                                     delta, garble,
                                     entry.get("lzh", False),
                                     entry.get("count", 0))
        f["type"] = entry.get("type", b"TEXT")
        f["creator"] = entry.get("creator", b"TLst")
        f["finderflags"] = entry.get("flags", 0)
        f["creation"] = created
        f["modification"] = modified
        head = b"\xAB\xCD\x00\x54" + _dd_header80(f)
        inner = len(head) + len(enc_d) + len(enc_r)
        trailer_bytes = head if trailer else b""
        span = inner + len(trailer_bytes)
        rec = _dd_ddar_record(
            leaf, span=span, rsrcsize=0,
            created=created, modified=modified,
            type=b"APPL", creator=b"DDAP", flags=0)
        out += rec + head + enc_d + enc_r + trailer_bytes
    folder_records(0)
    return bytes(out)


def dda2(entries, trailer=True, created=0xC9C00000,
         modified=0xC9C00000, markerless=False, junk_end=0):
    """A 'DDA2' archive.  Same entry dicts as ``ddar``.  ``markerless``
    omits the 0xBBBB end record; ``junk_end`` appends that many zero
    bytes after the last record in either case."""
    out = bytearray(b"DDA2" + b"\0" * 58)
    open_dirs = []
    folder_number = 2

    def drain(depth):
        while len(open_dirs) > depth:
            open_dirs.pop()

    for entry in entries:
        parts = entry["path"].split("/")
        dirs, leaf = parts[:-1], parts[-1]
        for i, d in enumerate(dirs):
            if i < len(open_dirs) and open_dirs[i] == d:
                continue
            drain(i)
            enc = d.encode("mac_roman")[:31]
            rec = bytearray(88)
            rec[0:4] = b"DDA2"
            struct.pack_into(">H", rec, 4, 0x8000)
            rec[6] = len(enc)
            rec[7:7 + len(enc)] = enc
            struct.pack_into(">II", rec, 38, i + 2, 88)
            struct.pack_into(">II", rec, 54, created, modified)
            struct.pack_into(">I", rec, 62, folder_number)
            folder_number += 1
            out += rec
            open_dirs.append(d)
        drain(len(dirs))

        data = entry["data"]
        rsrc = entry.get("rsrc", b"")
        leaf_enc = leaf.encode("mac_roman")[:31]
        depth = len(dirs) + 2

        if entry.get("raw"):
            total = 90 + len(data) + len(rsrc)
            rec = bytearray(90)
            rec[0:4] = b"DDA2"
            struct.pack_into(">H", rec, 4, 0x1000)
            rec[6] = len(leaf_enc)
            rec[7:7 + len(leaf_enc)] = leaf_enc
            struct.pack_into(">II", rec, 38, depth, total)
            struct.pack_into(">II", rec, 54, created, modified)
            rec[62:66] = entry.get("type", b"TEXT")
            rec[66:70] = entry.get("creator", b"TLst")
            struct.pack_into(">H", rec, 70, entry.get("flags", 0))
            struct.pack_into(">II", rec, 78, len(data), len(rsrc))
            rec[86] = dd_xsum(data)
            rec[87] = dd_xsum(rsrc)
            out += rec + data + rsrc
            continue

        method = entry.get("method", 0)
        rmethod = entry.get("rsrc_method", method)
        delta = entry.get("delta", False)
        garble = entry.get("garble", False)
        f, enc_d, enc_r = _dd_fields(data, rsrc, method, rmethod,
                                     delta, garble,
                                     entry.get("lzh", False),
                                     entry.get("count", 0))
        f["type"] = entry.get("type", b"TEXT")
        f["creator"] = entry.get("creator", b"TLst")
        f["finderflags"] = entry.get("flags", 0)
        f["creation"] = created
        f["modification"] = modified
        head = b"\xAB\xCD\x00\x54" + _dd_header80(f)
        trailer_bytes = head if trailer else b""
        total = 56 + len(head) + len(enc_d) + len(enc_r) + len(trailer_bytes)
        rec = bytearray(56)
        rec[0:4] = b"DDA2"
        struct.pack_into(">H", rec, 4, 0x0000)
        rec[6] = len(leaf_enc)
        rec[7:7 + len(leaf_enc)] = leaf_enc
        struct.pack_into(">II", rec, 38, depth, total)
        out += rec + head + enc_d + enc_r + trailer_bytes
    if not markerless:
        out += b"DDA2" + struct.pack(">H", 0xBBBB)
    if junk_end:
        out += b"\0" * junk_end
    return bytes(out)


# ------------------------------------------------------------------ #
# Now Compress                                                        #
# ------------------------------------------------------------------ #

def _canon_codes_from_lengths(lengths):
    """Symbol -> (code, length) for canonical MSB-first codes whose
    lengths are ``lengths`` (0 = unused).  Same arithmetic as the
    reader's table build."""
    count = [0] * 33
    maxlen = 0
    for value in lengths:
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
            raise ValueError("code lengths over-subscribe")
    codes = [None] * len(lengths)
    running = [0] * 33
    for symbol, value in enumerate(lengths):
        if value:
            codes[symbol] = (first[value] + running[value], value)
            running[value] += 1
    return codes


def _huffman_lengths(freq, count, label):
    """Code lengths for the symbols in ``freq`` (value -> count), or
    all zeros where unused.  Deepest code may not pass 15 — the
    format's 4-bit tables cannot hold more."""
    if not freq:
        raise ValueError("%s: no symbols to code" % label)
    symbols = sorted(freq)
    if len(symbols) == 1:
        lengths = [0] * count
        lengths[symbols[0]] = 1
        return lengths
    heap = [(weight, index, ("leaf", symbol))
            for index, (symbol, weight) in enumerate(sorted(freq.items()))]
    heapq.heapify(heap)
    counter = len(heap)
    while len(heap) > 1:
        w_a, _, a = heapq.heappop(heap)
        w_b, _, b = heapq.heappop(heap)
        heapq.heappush(heap, (w_a + w_b, counter, ("node", a, b)))
        counter += 1
    lengths = [0] * count

    def walk(node, depth):
        if depth > 15:
            raise ValueError("%s: code deeper than 15 bits" % label)
        if node[0] == "leaf":
            lengths[node[1]] = max(depth, 1)
            return
        walk(node[1], depth + 1)
        walk(node[2], depth + 1)

    walk(heap[0][2], 0)
    return lengths


def _huffman_region_encode(payload, nsyms):
    """One Huffman-coded region in Now Compress's framing: flush byte,
    ``nsyms`` 4-bit lengths (high nibble first), a count of
    extra-length entries (always 0 here), a pad to an even offset
    from the region's start, then the symbols, 16-bit aligned."""
    freq = Counter(payload)
    lengths = _huffman_lengths(freq, nsyms, "region")
    codes = _canon_codes_from_lengths(lengths)
    body = bytearray()
    table = bytearray()
    for i in range(nsyms // 2):
        table.append((lengths[2 * i] << 4) | lengths[2 * i + 1])
    if nsyms & 1:
        table.append(lengths[nsyms - 1] << 4)
    numbits = 0
    for symbol, weight in freq.items():
        numbits += codes[symbol][1] * weight
    # The flush byte is how much of the last 16-bit word was real,
    # (16 - pad) & 15; the decoder derives the payload length from the
    # region's length less (16 - flush) mod 16.
    flush = (-numbits) % 16
    if flush:
        flush = 16 - flush
    body.append(flush)
    body += table
    body.append(0)                      # no extra-length entries
    if len(body) & 1:
        body.append(0)                  # the stream starts on an even byte
    w = MsbBitWriter()
    for byte in payload:
        code, length = codes[byte]
        w.bits(code, length)
    pad = (-numbits) % 16
    if pad:
        w.bits(0, pad)
    body += w.to_bytes()
    return bytes(body)


def _now_lzss_stream(payload):
    """The shape-1 stream: the 00 03 prefix, then MSB-first flag
    bytes of eight tokens each (1 = literal, 0 = match).  A match is
    two bytes — a 3-bit length (plus 2) in the low bits of the first,
    a 13-bit distance split across it — unless the length field is 0,
    which escapes to a third byte carrying length - 2."""
    out = bytearray(b"\0\x03")
    tokens = []
    i = 0
    n = len(payload)
    while i < n:
        best_len, best_dist = 0, 0
        max_back = min(i, 8191)
        limit = n - i
        for dist in range(1, max_back + 1):
            length = 0
            while length < min(limit, 257) and payload[i + length - dist] == payload[i + length]:
                length += 1
            if length > best_len:
                best_len, best_dist = length, dist
                if best_len >= min(limit, 257):
                    break
        if best_len >= 3:
            tokens.append(("m", best_dist, best_len))
            i += best_len
        else:
            tokens.append(("l", payload[i]))
            i += 1
    idx = 0
    while idx < len(tokens):
        group = tokens[idx:idx + 8]
        flag = 0
        for token in group:
            flag = (flag << 1) | (1 if token[0] == "l" else 0)
        flag <<= 8 - len(group)         # unused flag bits read as zero
        out.append(flag)
        for token in group:
            if token[0] == "l":
                out.append(token[1])
            else:
                _, dist, length = token
                b0 = (dist >> 8) << 3
                if length <= 9:
                    b0 |= (length - 2) & 0x07
                    out += bytes([b0, dist & 0xFF])
                else:
                    out += bytes([b0, dist & 0xFF, length - 2])
        idx += 8
    return bytes(out)


def _shape3_len_class(length):
    from macextract.formats.now import NOW_LEN_BASE, NOW_LEN_EXTRA
    for sel in range(1, 0x22):
        lo = NOW_LEN_BASE[sel] + 2
        hi = lo + (1 << NOW_LEN_EXTRA[sel]) - 1
        if lo <= length <= hi:
            return sel
    raise ValueError("shape-3: no length class for %d" % length)


def _shape3_off_class(dist):
    from macextract.formats.now import NOW_OFF_BASE, NOW_OFF_EXTRA
    for sel in range(1, 0x38):
        lo = NOW_OFF_BASE[sel]
        hi = lo + (1 << NOW_OFF_EXTRA[sel]) - 1
        if lo <= dist <= hi:
            return sel
    raise ValueError("shape-3: no distance class for %d" % dist)


class NowEncoderState:
    """The encoder's view of the archive-wide window: a 32 KiB
    cache that each stream restarts from, built up as blocks decode."""

    def __init__(self):
        self.dict_cache = bytearray(32768)
        self.window = bytearray(32768)
        self.index = {}


def _shape3_block(chunk, state, is_first):
    """Encode one fork block with the archive coder.  Mutates
    ``state.window``/``state.index``; the caller updates
    ``state.dict_cache`` when this is the stream's first block."""
    from macextract.formats.now import (
        NOW_LEN_BASE, NOW_LEN_EXTRA, NOW_OFF_BASE, NOW_OFF_EXTRA)

    if is_first:
        state.window = bytearray(state.dict_cache)
        state.index = {}
        for pos in range(max(0, len(state.window) - 3)):
            state.index.setdefault(bytes(state.window[pos:pos + 3]),
                                   []).append(pos)

    window = state.window
    tokens = []
    i = 0
    n = len(chunk)
    while i < n:
        best_len, best_dist = 0, 0
        if i + 3 <= n:
            key = bytes(chunk[i:i + 3])
            candidates = state.index.get(key)
            limit = min(n - i, 257)
            if candidates:
                for pos in reversed(candidates[-64:]):
                    dist = len(window) - pos
                    if dist > 32768:
                        break
                    length = 0
                    while (length < limit and pos + length < len(window)
                           and window[pos + length] == chunk[i + length]):
                        length += 1
                    if length > best_len:
                        best_len, best_dist = length, dist
                        if length >= limit:
                            break
        if best_len >= 3:
            tokens.append(("m", best_dist, best_len))
            for k in range(best_len):
                window.append(chunk[i + k])
                key = bytes(window[-3:])
                state.index.setdefault(key, []).append(len(window) - 3)
            i += best_len
        else:
            tokens.append(("l", chunk[i]))
            window.append(chunk[i])
            key = bytes(window[-3:])
            state.index.setdefault(key, []).append(len(window) - 3)
            i += 1

    # Token bits, and the two code tables they need
    main_freq = Counter()
    off_freq = Counter()
    for token in tokens:
        if token[0] == "l":
            main_freq[token[1]] += 1
        else:
            _, dist, length = token
            main_freq[0x100 + _shape3_len_class(length)] += 1
            off_freq[_shape3_off_class(dist)] += 1

    main_lengths = _huffman_lengths(main_freq, 290, "main table")
    if not off_freq:
        off_freq = {0: 1}
    off_lengths = _huffman_lengths(off_freq, 56, "distance table")
    stored = [(value + 2) if value else 0 for value in off_lengths]
    tables_bytes = bytes(main_lengths) + bytes(stored)
    inner = _huffman_region_encode(tables_bytes, 20)
    headersize = len(inner)

    main_codes = _canon_codes_from_lengths(main_lengths)
    off_codes = _canon_codes_from_lengths(off_lengths)

    numbits = 0
    parts = []
    for token in tokens:
        if token[0] == "l":
            code, length = main_codes[token[1]]
            parts.append((code, length, 0, 0, None, None, None))
            numbits += length
            continue
        _, dist, length = token
        sel = _shape3_len_class(length)
        osel = _shape3_off_class(dist)
        code, length_bits = main_codes[0x100 + sel]
        extra = NOW_LEN_EXTRA[sel]
        eb = length - NOW_LEN_BASE[sel] - 2
        ocode, oextra = off_codes[osel]
        off_eb = dist - NOW_OFF_BASE[osel]
        parts.append((code, length_bits, extra, eb, ocode, oextra,
                      (off_eb, NOW_OFF_EXTRA[osel])))
        numbits += (length_bits + extra + oextra + NOW_OFF_EXTRA[osel]
                    if oextra else length_bits + extra + oextra)
    byte3 = (-numbits) % 16
    if byte3:
        byte3 = 16 - byte3

    header = bytearray()
    header += struct.pack(">H", 0x2F59 + headersize)
    header.append(0)                      # byte 2: unread by anything
    header.append(byte3)
    header += inner
    w = MsbBitWriter()
    for code, length_bits, extra, eb, ocode, oextra, off_part in parts:
        w.bits(code, length_bits)
        if extra:
            w.bits(eb, extra)
        if ocode is not None:
            w.bits(ocode, oextra)
            if off_part is not None:
                w.bits(off_part[0], off_part[1])
    pad = (-numbits) % 16
    if pad:
        w.bits(0, pad)
    header += w.to_bytes()
    return bytes(header)


def _sum32(data):
    return sum(data) & 0xFFFFFFFF


def _now_member_blocks(payload, method, state):
    """Encode one member's fork bytes (rsrc + data, rsrc first) into
    (mode, block_bytes) pairs.  ``method``: 0 stored, 1 LZSS (shape
    1), 0x20 Huffman only, 0x21 Huffman then LZSS, 0x40 shape 3."""
    if method == 0:
        return [(0, payload)] if payload else []
    if method == 1:
        return [(1, _now_lzss_stream(payload))]
    if method == 0x20:
        return [(0x20, _huffman_region_encode(payload[i:i + 0x8000], 0x100))
                for i in range(0, len(payload), 0x8000)]
    if method == 0x21:
        return [(0x21, _huffman_region_encode(
                    _now_lzss_stream(payload[i:i + 0x8000]), 0x100))
                for i in range(0, len(payload), 0x8000)]
    if method == 0x40:
        chunks = [payload[i:i + 0x8000]
                  for i in range(0, len(payload), 0x8000)]
        return [(0x40, _shape3_block(chunk, state, i == 0))
                for i, chunk in enumerate(chunks)]
    raise ValueError("now: unsupported method %d" % method)


def now_archive(entries, trailer=True, created=0xC9C00000,
                modified=0xC9C00000):
    """A Now Compress file or archive built from ``entries``.

    Each entry is a dict with ``path`` ('/'-separated; folders are
    derived from the paths), ``data``, and optionally ``rsrc``,
    ``type``, ``creator``, ``method`` (0, 1, 0x20, 0x21, 0x40), and
    ``finder_flags``.  A fork pair of zero bytes produces a member
    with no data area.  ``trailer`` adds the 16-byte archive trailer;
    without it the file ends exactly where the last member's data
    area does.
    """
    # Expand paths into emission order (folders first, depth-first),
    # deriving each directory's direct-child count from the entry list.
    order = []
    open_dirs = []

    def close_past(depth):
        while len(open_dirs) > depth:
            open_dirs.pop()

    for entry in entries:
        parts = entry["path"].split("/")
        dirs, leaf = parts[:-1], parts[-1]
        for i, d in enumerate(dirs):
            if i < len(open_dirs) and open_dirs[i] == d:
                continue
            close_past(i)
            open_dirs.append(d)
            order.append(("dir", tuple(dirs[:i + 1])))
        close_past(len(dirs))
        order.append(("file", tuple(parts), entry))
    close_past(0)

    # Direct-child count for every folder in the tree, derived dirs
    # included: count paths one level below each folder.
    all_paths = set()
    for entry in entries:
        parts = entry["path"].split("/")
        for i in range(1, len(parts) + 1):
            all_paths.add(tuple(parts[:i]))
    dir_counts = {}
    for path in all_paths:
        prefix = path
        count = sum(1 for other in all_paths
                    if other[:len(prefix)] == prefix and len(other) == len(prefix) + 1)
        dir_counts["/".join(path)] = count

    record_size = 110
    header_size = 24
    cursor = header_size + record_size * len(order)
    state = NowEncoderState()
    members = {}
    area_bounds = {}
    for kind, *rest in order:
        if kind != "file":
            continue
        path, entry = rest[0], rest[1]
        key = "/".join(path)
        data_fork = entry.get("data", b"")
        rsrc = entry.get("rsrc", b"")
        forkpair = rsrc + data_fork
        if not forkpair:
            area_bounds[key] = (cursor, cursor)
            continue
        blocks = _now_member_blocks(forkpair, entry.get("method", 0), state)
        table_size = 4 + 8 * len(blocks) + 8
        first = cursor + table_size
        area = bytearray(struct.pack(">I", first))
        endoff = first
        recs = []
        for mode, block in blocks:
            endoff += len(block) + 4
            recs.append((mode, endoff))
        at = 4
        total = first
        for mode, block_end in recs:
            rec = struct.pack(">HHI", mode, 0, block_end)
            area += rec
            total += _sum32(rec)
            at += 8
        area += b"\0\0\0\0"
        total += 0
        area += struct.pack(">I", total & 0xFFFFFFFF)
        for mode, block in blocks:
            area += block + struct.pack(">I", _sum32(block))
        members[key] = bytes(area)
        area_bounds[key] = (cursor, cursor + len(area))
        cursor += len(area)

    out = bytearray(b"\0\x02" + b"\0" * 6)
    out += struct.pack(">I", len(order))
    out += b"\0" * 12
    assert len(out) == header_size

    for item in order:
        if item[0] == "dir":
            path = item[1]
            rec = bytearray(record_size)
            leaf = path[-1].encode("mac_roman")[:31]
            rec[0] = len(leaf)
            rec[1:1 + len(leaf)] = leaf
            struct.pack_into(">H", rec, 36, 0x10)
            struct.pack_into(">II", rec, 54, created, modified)
            struct.pack_into(">H", rec, 82,
                             dir_counts.get("/".join(path), 0))
            rec[106:110] = struct.pack(">I", _sum32(rec[:106]))
            out += rec
            continue
        path, entry = item[1], item[2]
        key = "/".join(path)
        rec = bytearray(record_size)
        leaf = path[-1].encode("mac_roman")[:31]
        rec[0] = len(leaf)
        rec[1:1 + len(leaf)] = leaf
        rec[38:42] = entry.get("type", b"TEXT")
        rec[42:46] = entry.get("creator", b"TLst")
        struct.pack_into(">H", rec, 46, entry.get("finder_flags", 0))
        struct.pack_into(">II", rec, 54, created, modified)
        data_fork = entry.get("data", b"")
        rsrc = entry.get("rsrc", b"")
        start, end = area_bounds.get(key, (cursor, cursor))
        struct.pack_into(">I", rec, 86, len(data_fork))
        struct.pack_into(">I", rec, 90, len(rsrc))
        struct.pack_into(">I", rec, 98, start)
        struct.pack_into(">I", rec, 102, end)
        rec[106:110] = struct.pack(">I", _sum32(rec[:106]))
        out += rec

    for item in order:
        if item[0] != "file":
            continue
        area = members.get("/".join(item[1]))
        if area:
            out += area
    if trailer:
        tail = bytearray(16)
        struct.pack_into(">I", tail, 0, cursor)
        struct.pack_into(">H", tail, 4, 1)
        struct.pack_into(">H", tail, 10, 1)
        struct.pack_into(">I", tail, 12, _sum32(tail[:12]))
        out += tail
    return bytes(out)


def compress_encode(payload, maxbits=16, blockmode=True, force_clear=False):
    """Unix compress(1) writer: ``1f 9d`` header and flags byte (low 5
    bits the max code width, 0x80 the block bit), then LSB-first LZW
    codes starting at 9 bits.  The code width widens exactly as the
    decoder widens: after the decoder's table reaches a power of two,
    and not one bit earlier — the encoder's own table runs one entry
    ahead, so the schedule is counted against the decoder's view, not
    this one's.  A full table stops inserting (saturation), which is
    how the real encoder behaves on modest inputs: the block-mode
    clear 256 is a ratio-triggered escape, not a hard cap, and no
    corpus available here shows one even at 717 KB.
    ``force_clear=True`` emits clear 256 at the table boundary,
    producing streams no real decompressor accepts (checked against
    ncompress, gzip and busybox at maxbits 9); it exists only to
    grade this decoder's clear path for self-consistency.  Needed to
    grade the .Z reader end to end."""
    bits = []

    def put(value, nbits):
        for i in range(nbits):
            bits.append((value >> i) & 1)

    clear = 256
    full = 1 << maxbits
    next_code = clear + 1 if blockmode else 256
    symbolsize = 9
    dec_ns = clear + 1 if blockmode else 256   # width the DECODER is in
    first_code = True
    group = 0                                   # codes in the current 8-code group

    def fresh():
        return {bytes([i]): i for i in range(256)}

    def pad_group():
        nonlocal group
        if group:
            for _ in range((8 - group) * symbolsize):
                bits.append(0)
        group = 0

    def emit(code):
        nonlocal symbolsize, dec_ns, first_code, group
        put(code, symbolsize)
        group = (group + 1) % 8
        if not first_code and dec_ns < full:
            dec_ns += 1
            if dec_ns & (dec_ns - 1) == 0 and symbolsize < maxbits:
                symbolsize += 1
        first_code = False

    table = fresh()
    current = b""
    for byte in payload:
        current += bytes([byte])
        if current in table:
            continue
        emit(table[current[:-1]])
        if next_code < full:
            table[current] = next_code
            next_code += 1
        elif blockmode and force_clear:
            # The decoder discards the remainder of the 8-code group
            # once it reads clear, so the encoder pads this group to
            # its boundary too.
            emit(clear)
            pad_group()
            dec_ns = clear + 1
            symbolsize = 9
            first_code = True
            next_code = clear + 1
            table = fresh()
        # full table without force_clear: keep coding with what exists
        current = current[-1:]
    if current:
        emit(table[current])
    out = bytearray(3)
    out[0] = 0x1F
    out[1] = 0x9D
    out[2] = (maxbits & 0x1F) | (0x80 if blockmode else 0)
    body = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for j, bit in enumerate(bits[i:i + 8]):
            value |= bit << j
        body.append(value)
    return bytes(out + body)


def garble_xor(buf, password):
    """ARC's garble: XOR the upper-cased password over a member's
    compressed bytes, by position from the first byte again at every
    member.  The password is upper-cased before it is used."""
    pw = password.encode("latin-1") if isinstance(password, str) else bytes(password)
    pw = bytes(b - 32 if 97 <= b <= 122 else b for b in pw)
    if not pw:
        return bytes(buf)
    length = len(pw)
    return bytes(b ^ pw[i % length] for i, b in enumerate(buf))


def squeeze_encode(payload):
    """Method 4's coder, test-side: build a Huffman-like tree from the
    byte frequencies of the payload (plus symbol 256 as the stream's
    terminator), emit it as a little-endian u16 pair count then that
    many pairs of little-endian s16 — a negative value is a leaf
    holding symbol ``-value - 1``; a non-negative value is the index
    of another pair — then bit-pack the codes LSB-first, one bit per
    step from the root, the bit picking the pair's child.  The root is
    pair 0.  Not every formatting decision here matches a real ARC
    squeeze encoder; this one only has to round-trip through the
    decoder."""
    import heapq
    from collections import Counter

    freq = Counter(payload)
    freq[256] = freq.get(256, 0) + 1
    dummy = 0
    while len(freq) < 2:
        if dummy not in freq:
            freq[dummy] = 1
        dummy += 1
    heap = []
    serial = 0
    for symbol, count in freq.items():
        heapq.heappush(heap, (count, serial, ("leaf", symbol)))
        serial += 1
    while len(heap) > 1:
        first = heapq.heappop(heap)
        second = heapq.heappop(heap)
        heapq.heappush(heap, (first[0] + second[0], serial,
                              ("node", first[2], second[2])))
        serial += 1
    root = heap[0][2]

    pairs = []
    codes = {}

    def walk(node, code, depth):
        if node[0] == "leaf":
            codes[node[1]] = (code, depth)
            return -(node[1] + 1)
        index = len(pairs)
        pairs.append(None)
        left = walk(node[1], code, depth + 1)              # bit 0
        right = walk(node[2], code | (1 << depth), depth + 1)   # bit 1
        pairs[index] = (left, right)
        return index

    walk(root, 0, 0)
    out = bytearray(struct.pack("<H", len(pairs)))
    for left, right in pairs:
        out += struct.pack("<hh", left, right)
    writer = LsbBitWriter()
    for symbol in list(payload) + [256]:
        code, numbits = codes[symbol]
        writer.put(code, numbits)
    out += writer.flush()
    return bytes(out)


def arc(entries, garble=None, end_marker=True):
    """Build an ARC archive in memory.

    Each entry dict carries ``name``, ``data`` and a ``method``
    (default 2, stored).  ``date`` and ``time`` are the MS-DOS date
    and time words stored in the header (defaults: 2020-06-15
    12:00:00).  Method 1 writes the short header with no original
    size.  Members are laid end to end and the archive ends with a
    lone ``1a 00`` unless ``end_marker=False``.  A member's CRC-16/ARC
    covers the DECODED bytes.  ``garble=<password>`` XORs the
    upper-cased password over each member's COMPRESSED bytes,
    resetting the position to the password's first byte at every
    member; the header is not garbled.
    """
    out = bytearray()
    for spec in entries:
        name = spec["name"]
        raw = name.encode("mac_roman") if isinstance(name, str) else bytes(name)
        if len(raw) > 13:
            raise ValueError("ARC member name is longer than 13 bytes")
        method = spec.get("method", 2)
        data = bytes(spec["data"])
        date = spec.get("date", 0x50CF)          # 2020-06-15
        time = spec.get("time", 0x6000)          # 12:00:00
        if method in (1, 2):
            comp = data
        elif method == 3:
            comp = rle90_encode(data)
        elif method == 4:
            comp = squeeze_encode(rle90_encode(data))
        elif method == 8:
            comp = b"\x0c" + lzw_compress(rle90_encode(data),
                                          maxbits=12, blockmode=True)
        elif method == 9:
            comp = lzw_compress(data, maxbits=13, blockmode=True)
        else:
            # The refused methods are never decoded; the payload is
            # stored raw so a refusal can be graded on the header.
            comp = data
        if garble is not None:
            comp = garble_xor(comp, garble)
        crc = crc16_arc(data)
        header = b"\x1a" + bytes([method]) + raw.ljust(13, b"\0")
        if method == 1:
            header += struct.pack("<IHHH", len(comp), date, time, crc)
        else:
            header += struct.pack("<IHHHI", len(comp), date, time, crc,
                                  len(data))
        out += header + comp
    if end_marker:
        out += b"\x1a\x00"
    return bytes(out)


# ------------------------------------------------------------------ #
# LZH/LHA (.lzh, .lha)                                                #
# ------------------------------------------------------------------ #

_LH_WBITS = {b"-lh4-": 12, b"-lh5-": 13, b"-lh6-": 15, b"-lh7-": 16}


def _lzh_off_sym(dist):
    """The offset table's symbol for a distance: the bit width of the
    distance, whose top bit the decoder then implies."""
    if dist == 1:
        return 0
    if dist == 2:
        return 1
    return (dist - 1).bit_length()


def _lzh_tokens(payload, wsize):
    """LZSS tokens — ``("l", byte)`` and ``("m", dist, length)`` —
    from a hash chain over the payload.  A match never reaches beyond
    the window or 256 bytes, and never back past the start."""
    n = len(payload)
    head = {}
    prev = [-1] * n
    tokens = []
    i = 0
    while i < n:
        best_len = 0
        best_dist = 0
        if i + 3 <= n:
            limit = min(256, n - i)
            h = (payload[i] << 16) | (payload[i + 1] << 8) | payload[i + 2]
            j = head.get(h, -1)
            for _ in range(64):
                if j < 0 or i - j > wsize:
                    break
                length = 0
                while (length < limit
                       and payload[j + length] == payload[i + length]):
                    length += 1
                if length > best_len:
                    best_len = length
                    best_dist = i - j
                    if best_len >= limit:
                        break
                j = prev[j]
        if best_len >= 3:
            tokens.append(("m", best_dist, best_len))
            span = best_len
        else:
            tokens.append(("l", payload[i]))
            span = 1
        for k in range(i, i + span):
            if k + 3 <= n:
                h = ((payload[k] << 16) | (payload[k + 1] << 8)
                     | payload[k + 2])
                prev[k] = head.get(h, -1)
                head[h] = k
        i += span
    return tokens


def _lzh_huffman(freq, cap):
    """Huffman lengths for ``freq`` (symbol -> count); raises when a
    code would pass ``cap`` bits."""
    heap = [(weight, index, ("leaf", symbol))
            for index, (symbol, weight) in enumerate(sorted(freq.items()))]
    heapq.heapify(heap)
    counter = len(heap)
    while len(heap) > 1:
        weight_a, _, node_a = heapq.heappop(heap)
        weight_b, _, node_b = heapq.heappop(heap)
        heapq.heappush(heap, (weight_a + weight_b, counter,
                              ("node", node_a, node_b)))
        counter += 1
    lengths = {}

    def walk(node, depth):
        if depth > cap:
            raise ValueError("LZH: code deeper than %d bits" % cap)
        if node[0] == "leaf":
            lengths[node[1]] = max(depth, 1)
            return
        walk(node[1], depth + 1)
        walk(node[2], depth + 1)

    walk(heap[0][2], 0)
    return lengths


def _lzh_command_lengths(freq):
    """Command-table lengths: Huffman, deepest code capped at 28 (the
    temporary table's alphabet is 31 wide, so ``length + 2`` must fit
    inside it), falling back to flat codes when the payload's own
    frequencies run deeper."""
    if len(freq) == 1:
        return {next(iter(freq)): 1}
    try:
        return _lzh_huffman(freq, 28)
    except ValueError:
        symbols = sorted(freq)
        flat = max(1, (len(symbols) - 1).bit_length())
        return {symbol: flat for symbol in symbols}


def _lzh_put_length(writer, value):
    """One table length: three bits, and a 7 says a unary tail
    extends it (that many ones, then a zero)."""
    if value < 7:
        writer.bits(value, 3)
        return
    writer.bits(7, 3)
    for _ in range(value - 7):
        writer.bit(1)
    writer.bit(0)


def _lzh_block(writer, cmds, offbits):
    """One block into the stream's shared bit writer: a 16-bit
    command count, the temporary table, the command table coded
    through it, the offset table, then the commands themselves — all
    most-significant-bit first.  Blocks are NOT byte-aligned; only
    the stream's end is padded."""
    freq = Counter()
    offs = set()
    for token in cmds:
        if token[0] == "l":
            freq[token[1]] += 1
        else:
            freq[256 + token[2] - 3] += 1
            offs.add(_lzh_off_sym(token[1]))

    lengths = _lzh_command_lengths(freq)
    n_code = max(lengths) + 1
    code_lengths = [lengths.get(symbol, 0) for symbol in range(n_code)]
    codes = _canon_codes_from_lengths(code_lengths)

    # The temporary table codes the command table's own lengths: 0
    # skips one unused code, anything else is the length plus two.
    temp_syms = {0} | {value + 2 for value in lengths.values()}
    n_temp = max(temp_syms) + 1
    temp_width = max(1, (len(temp_syms) - 1).bit_length())
    temp_lengths = [temp_width if symbol in temp_syms else 0
                    for symbol in range(n_temp)]
    temp_codes = _canon_codes_from_lengths(temp_lengths)

    writer.bits(len(cmds), 16)

    writer.bits(n_temp, 5)
    for index, value in enumerate(temp_lengths):
        _lzh_put_length(writer, value)
        if index == 2 and n_temp > 2:
            writer.bits(0, 2)        # the skip field after the 3rd

    writer.bits(n_code, 9)
    for value in code_lengths:
        symbol = 0 if value == 0 else value + 2
        code, width = temp_codes[symbol]
        writer.bits(code, width)

    if offs:
        n_off = max(offs) + 1
        off_width = max(1, (len(offs) - 1).bit_length())
        off_lengths = [off_width if symbol in offs else 0
                       for symbol in range(n_off)]
        off_codes = _canon_codes_from_lengths(off_lengths)
        writer.bits(n_off, offbits)
        for value in off_lengths:
            _lzh_put_length(writer, value)
    else:
        off_codes = None
        writer.bits(0, offbits)      # one symbol, no bits at all
        writer.bits(0, offbits)

    for token in cmds:
        if token[0] == "l":
            symbol = token[1]
        else:
            symbol = 256 + token[2] - 3
        code, width = codes[symbol]
        writer.bits(code, width)
        if token[0] == "m":
            dist = token[1]
            bits = _lzh_off_sym(dist)
            code, width = off_codes[bits]
            writer.bits(code, width)
            if bits >= 2:
                writer.bits(dist - (1 << (bits - 1)) - 1, bits - 1)


def _lzh_encode(payload, wbits, empty_block=False):
    """-lh4- .. -lh7-: the token stream cut into blocks of at most
    4096 commands, each with its own three tables, all in one bit
    stream that is padded to a byte only at its end."""
    tokens = _lzh_tokens(payload, 1 << wbits)
    if not tokens:
        return b""
    offbits = 4 if wbits < 15 else 5
    writer = MsbBitWriter()
    if empty_block:
        # An empty block: a zero count, then three tables each saying
        # "one symbol, no bits at all".
        writer.bits(0, 16)
        writer.bits(0, 5)
        writer.bits(0, 5)
        writer.bits(0, 9)
        writer.bits(0, 9)
        writer.bits(0, offbits)
        writer.bits(0, offbits)
    for start in range(0, len(tokens), 4096):
        _lzh_block(writer, tokens[start:start + 4096], offbits)
    return writer.to_bytes()


def lha(entries, end_marker=True):
    """Build an LZH/LHA archive in memory.

    Each entry dict carries ``name`` and ``data``; ``method`` defaults
    to ``-lh5-`` and ``level`` to 1.  Levels 0 and 1 store an MS-DOS
    date/time word pair (``date``/``time``, defaults 2020-06-15
    12:00:00) and the name field; levels 2 and 3 store a Unix time
    (``unix_time``) and take the name from the extended headers.
    Extra keys: ``os`` (the OS byte, levels 1-3, default ``'U'``),
    ``attr`` (default 0x20), ``unix_area`` (level 0's ``U`` area),
    ``filename_ext``/``path_ext`` (0x01/0x02 extended headers),
    ``mode`` (0x50), ``mtime54`` (0x54), ``comment`` (0x3f),
    ``exts`` (a list of raw ``(type, payload)`` pairs), ``short``
    (level 0's CRC-less LArc header), ``bad_crc``/``bad_csum``,
    ``empty_block`` (an empty block in front of the real one),
    ``level3_word`` (the word-size field), ``os9`` (OS-9/68k's
    two-short level 2 size) and ``dir`` (an ``-lhd-`` marker).
    Refused methods are written with their payload stored raw: only
    the header is graded.  The archive ends with a lone zero byte
    unless ``end_marker=False``.
    """
    out = bytearray()
    for spec in entries:
        name = spec["name"]
        raw = name.encode("mac_roman") if isinstance(name, str) \
            else bytes(name)
        data = bytes(spec["data"])
        level = spec.get("level", 1)
        method = spec.get("method", "-lh5-")
        if isinstance(method, str):
            method = method.encode("ascii")
        if spec.get("dir"):
            method = b"-lhd-"
        if method in _LH_WBITS:
            comp = _lzh_encode(data, _LH_WBITS[method],
                               spec.get("empty_block", False))
        elif method in (b"-lh0-", b"-lz4-", b"-lhd-"):
            comp = data
        else:
            comp = data            # refused: only the header is graded

        attr = spec.get("attr", 0x20)
        crc = crc16_arc(data)
        if spec.get("bad_crc"):
            crc ^= 0xFFFF
        unix_time = spec.get("unix_time", 1592222400)   # 2020-06-15
        dos_date = spec.get("date", 0x50CF)
        dos_time = spec.get("time", 0x6000)
        mode = spec.get("mode", 0o644)
        os_id = spec.get("os", 0x55)                    # 'U'

        # The extended headers, one (type, payload) pair each.  The
        # mode key is level 0's U-area there and a 0x50 header above.
        exts = []
        for key, kind in (("filename_ext", 0x01), ("path_ext", 0x02),
                          ("comment", 0x3f), ("mode", 0x50),
                          ("mtime54", 0x54)):
            if key == "mode" and level == 0:
                continue
            if key in spec and spec[key] is not None:
                value = spec[key]
                if isinstance(value, str):
                    value = value.encode("mac_roman")
                elif isinstance(value, int):
                    width = 2 if kind in (0x50,) else 4
                    value = struct.pack("<I" if width == 4 else "<H",
                                        value)
                exts.append((kind, bytes(value)))
        exts.extend((kind, bytes(value))
                    for kind, value in spec.get("exts", ()))

        if level in (0, 1) or level > 3:
            if level == 1 and spec.get("short"):
                raise ValueError("LHA: only level 0 has a short header")
            n = len(raw)
            if level == 0:
                if spec.get("unix_area"):
                    hdrsize = 36 + n
                elif spec.get("short"):
                    hdrsize = 22 + n
                else:
                    hdrsize = 24 + n
            else:
                hdrsize = 27 + n      # base, then the first size word
            if hdrsize - 2 > 0xFF:
                raise ValueError("LHA: level 0/1 name is too long")
            if exts and level == 0:
                raise ValueError("LHA: only level 1 has ext headers")

            header = bytearray(hdrsize if level == 0 else 25 + n)
            header[2:7] = method
            if level == 1:
                skip = sum(3 + len(payload) for _, payload in exts)
                struct.pack_into("<I", header, 7, skip + len(comp))
            else:
                struct.pack_into("<I", header, 7, len(comp))
            struct.pack_into("<I", header, 11, len(data))
            struct.pack_into("<HH", header, 15, dos_time, dos_date)
            header[19] = attr
            header[20] = level
            header[21] = n
            header[22:22 + n] = raw
            if level == 0:
                if not spec.get("short"):
                    struct.pack_into("<H", header, 22 + n, crc)
                if spec.get("unix_area"):
                    header[24 + n] = ord("U")
                    header[25 + n] = 0            # minor version
                    struct.pack_into("<I", header, 26 + n, unix_time)
                    struct.pack_into("<H", header, 30 + n, mode)
                    struct.pack_into("<HH", header, 32 + n, 100, 0)
                header[0] = hdrsize - 2
                header[1] = sum(header[2:]) & 0xFF
            else:
                struct.pack_into("<H", header, 22 + n, crc)
                header[24 + n] = os_id
                for kind, payload in exts:
                    header += (struct.pack("<H", 3 + len(payload))
                               + bytes([kind]) + payload)
                header += b"\x00\x00"            # the terminator
                header[0] = 25 + n
                # The sum covers the base and the first size word —
                # everything the header size byte counts.
                header[1] = sum(header[2:27 + n]) & 0xFF
            if spec.get("bad_csum"):
                if level not in (0, 1):
                    raise ValueError("LHA: only levels 0 and 1 have"
                                     " a sum")
                header[1] ^= 0xFF

        elif level == 2:
            if spec.get("short") or spec.get("unix_area"):
                raise ValueError("LHA: short headers and the U area"
                                 " are level 0 only")
            chain = bytearray()
            for kind, payload in exts:
                chain += (struct.pack("<H", 3 + len(payload))
                          + bytes([kind]) + payload)
            chain += b"\x00\x00"
            total = 24 + len(chain)
            if total & 0xFF == 0:                # the low byte must
                chain += b"\x00"                 # not be zero
                total += 1
            header = bytearray(24)
            struct.pack_into("<H", header, 0, total)
            header[2:7] = method
            struct.pack_into("<I", header, 7, len(comp))
            struct.pack_into("<I", header, 11, len(data))
            struct.pack_into("<I", header, 15, unix_time)
            header[19] = attr
            header[20] = 2
            struct.pack_into("<H", header, 21, crc)
            header[23] = ord("K") if spec.get("os9") else os_id
            if spec.get("os9"):
                # LHA for OS-9/68k writes the length of the REST of
                # the header: two bytes short.
                struct.pack_into("<H", header, 0, total - 2)
            header += chain
            if spec.get("bad_csum"):
                raise ValueError("LHA: levels 2 and 3 have no sum")

        elif level == 3:
            if spec.get("short") or spec.get("unix_area"):
                raise ValueError("LHA: short headers and the U area"
                                 " are level 0 only")
            chain = bytearray()
            for kind, payload in exts:
                chain += (struct.pack("<I", 5 + len(payload))
                          + bytes([kind]) + payload)
            chain += b"\x00\x00\x00\x00"
            total = 28 + len(chain)
            header = bytearray(28)
            struct.pack_into("<H", header, 0, spec.get("level3_word", 4))
            header[2:7] = method
            struct.pack_into("<I", header, 7, len(comp))
            struct.pack_into("<I", header, 11, len(data))
            struct.pack_into("<I", header, 15, unix_time)
            header[19] = attr
            header[20] = 3
            struct.pack_into("<H", header, 21, crc)
            header[23] = os_id
            struct.pack_into("<I", header, 24, total)
            header += chain
            if spec.get("bad_csum"):
                raise ValueError("LHA: levels 2 and 3 have no sum")

        else:
            raise ValueError("LHA: header level %d is not written"
                             % level)

        out += header + comp
    if end_marker:
        out += b"\x00"
    return bytes(out)


def _fold_fork_crcs(res_crc, data_crc, chunk, pos, rsrc_len):
    """Fold a part's payload into the running resource/data fork sums."""
    i = 0
    p = pos
    while i < len(chunk):
        if p < rsrc_len:
            n = min(len(chunk) - i, rsrc_len - p)
            res_crc = crc16_arc(chunk[i:i + n], res_crc)
        else:
            n = len(chunk) - i
            data_crc = crc16_arc(chunk[i:i + n], data_crc)
        p += n
        i += n
    return res_crc, data_crc


def sitseg_parts(name=b"TestFile", data=b"hello world", rsrc=b"",
                 type=b"TEXT", creator=b"ttxt", flags=0,
                 created=400000000, modified=400000100,
                 set_id=b"\x41\xa7", chunks=None):
    """Build a StuffIt segmented set. ``chunks`` is the payload size of
    each part; defaults to two parts cut near the halfway point.
    Returns the part images as a list of bytes, part 1 first.

    Forks join resource-first: payload = rsrc + data.
    """
    payload = bytes(rsrc) + bytes(data)
    if chunks is None:
        half = (len(payload) + 1) // 2
        chunks = [half, len(payload) - half]
    parts = []
    pos = 0
    res_crc = 0
    data_crc = 0
    rsrc_len = len(rsrc)
    fp = struct.pack(">4s4sHIIII", type, creator, flags, created, modified,
                    len(rsrc), len(data))
    assert len(fp) == 26
    for index, size in enumerate(chunks, 1):
        chunk = payload[pos:pos + size]
        res_crc, data_crc = _fold_fork_crcs(res_crc, data_crc, chunk, pos,
                                            rsrc_len)
        pos += len(chunk)
        head = bytearray(100)
        head[0:2] = set_id
        head[2] = 0
        head[3] = index
        head[4] = len(name)
        head[5:5 + len(name)] = name
        head[68:94] = fp
        struct.pack_into(">H", head, 96, res_crc)
        struct.pack_into(">H", head, 98, data_crc)
        struct.pack_into(">H", head, 94, crc16_arc(bytes(head[:94])))
        parts.append(bytes(head) + chunk)
    return parts


def splt_parts(name_unused=None, data=b"hello world", rsrc=b"",
               type=b"TEXT", creator=b"ttxt", flags=0,
               created=400000000, modified=400000100,
               tick=12345, chunks=None):
    """Build a DiskDoubler ``SPLT`` set. ``chunks`` is the payload size of
    each part; defaults to two parts cut near the halfway point.
    Returns the part images as a list of bytes, part 1 first.

    Forks join data-first: payload = data + rsrc. There is no name.
    """
    payload = bytes(data) + bytes(rsrc)
    if chunks is None:
        half = (len(payload) + 1) // 2
        chunks = [half, len(payload) - half]
    nparts = len(chunks)
    assert nparts <= 256
    parts = []
    pos = 0
    for index in range(nparts):
        size = chunks[index]
        chunk = payload[pos:pos + size]
        pos += len(chunk)
        head = bytearray(94)
        head[0:4] = b"SPLT"
        struct.pack_into(">I", head, 4, tick)
        struct.pack_into(">II", head, 8, len(data), len(rsrc))
        head[16:20] = type
        head[20:24] = creator
        struct.pack_into(">H", head, 24, flags)
        struct.pack_into(">II", head, 32, modified, created)
        struct.pack_into(">H", head, 40, nparts)
        struct.pack_into(">H", head, 42, index)
        struct.pack_into(">I", head, 44, len(chunk))
        struct.pack_into(">H", head, 48, crc16_ccitt(chunk))
        head[90:94] = b"SPLT"
        parts.append(bytes(head) + chunk)
    return parts


MAR_MAGIC = 0x4D415280
MAR_FILE = 0x66696C65           # 'file'
MAR_FOLDER = 0x666F6C64         # 'fold'
MAR_END = 0x2D2D2D2D            # '----'


def _mar_crc32(buf, crc=0):
    """The MAR CRC-32: MSB-first, polynomial 0x1EDC6F41, init 0, no xorout."""
    for byte in buf:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x1EDC6F41) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def _mar_record(rec_id, name_pstr, data_size, rsrc_size, comment_size,
                file_flags, created, modified, finfo16, scroll4, bad_crc):
    hdr = bytearray(128)
    struct.pack_into(">I", hdr, 0, MAR_MAGIC)
    struct.pack_into(">I", hdr, 4, rec_id)
    assert len(name_pstr) <= 63
    hdr[8] = len(name_pstr)
    hdr[9:9 + len(name_pstr)] = name_pstr
    struct.pack_into(">IIII", hdr, 72, data_size, rsrc_size, comment_size,
                     file_flags)
    struct.pack_into(">II", hdr, 88, created, modified)
    hdr[96:112] = finfo16
    hdr[112:116] = scroll4
    crc = _mar_crc32(bytes(hdr[:124]))
    if bad_crc:
        crc ^= 0xFFFFFFFF
    struct.pack_into(">I", hdr, 124, crc)
    return bytes(hdr)


def _mar_block(payload, bad_crc):
    if len(payload) == 0:
        return b""
    crc = _mar_crc32(payload)
    if bad_crc:
        crc ^= 0xFFFFFFFF
    pad = (128 - ((len(payload) + 4) & 127)) & 127
    return payload + struct.pack(">I", crc) + b"\0" * pad


def _mar_pstr(name_bytes):
    assert len(name_bytes) <= 63
    return bytes(name_bytes)


def mar(entries, bad_header_crc=False, bad_block_crc=False):
    """Build a stored (uncompressed) MAR archive in memory.

    Each item dict carries ``name`` — a path with ``/`` separators;
    folders along the path are created implicitly.  Files carry
    ``data`` and/or ``rsrc`` bytes.  Extra keys: ``type``, ``creator``
    (four bytes), ``flags`` (finder flags, u16), ``file_flags`` (u32,
    bit 0 locked, bit 1 protected), ``created``, ``modified`` (Mac
    1904-epoch seconds), ``comment`` (bytes), ``finfo`` (16 raw
    Finder bytes, overriding the type/creator/flags build),
    ``folder`` (True: a folder record, possibly empty), ``dinfo`` (a
    folder's 16 DInfo bytes), ``scroll`` (a folder's 4 frScroll
    bytes), ``raw_name`` (bytes: the leaf name used verbatim, for a
    leaf whose name contains ``/``).
    """
    tree = {"children": {}, "spec": None}

    def node_for(parts):
        node = tree
        for part in parts:
            key = part if isinstance(part, bytes) else part.encode("mac_roman")
            node = node["children"].setdefault(
                key, {"children": {}, "spec": None, "key": key})
        return node

    for spec in entries:
        if spec.get("raw_name") is not None:
            parts = [spec["raw_name"]]
        else:
            parts = spec["name"].split("/")
        node = node_for(parts)
        node["spec"] = spec

    out = bytearray()

    def emit(node):
        spec = node["spec"] or {}
        is_folder = bool(spec.get("folder")) or bool(node["children"])
        if is_folder:
            created = spec.get("created", 0)
            modified = spec.get("modified", 0)
            file_flags = spec.get("file_flags", 0x00000010)  # MF_FILE_ISDIR
            dinfo = spec.get("dinfo", b"\0" * 16)
            scroll = spec.get("scroll", b"\0" * 4)
            data = bytes(spec.get("data", b""))
            rsrc = bytes(spec.get("rsrc", b""))
            comment = bytes(spec.get("comment", b""))
            out.extend(_mar_record(MAR_FOLDER, _mar_pstr(node["key"]),
                               len(data), len(rsrc), len(comment),
                               file_flags, created, modified, dinfo,
                               scroll, bad_header_crc))
            out.extend(_mar_block(data, bad_block_crc))
            out.extend(_mar_block(rsrc, bad_block_crc))
            out.extend(_mar_block(comment, bad_block_crc))
            for child in node["children"].values():
                emit(child)
            out.extend(_mar_record(MAR_END, b"", 0, 0, 0, 0, 0, 0,
                               b"\0" * 16, b"\0" * 4, bad_header_crc))
            return

        name_bytes = node["key"]
        data = bytes(spec.get("data", b""))
        rsrc = bytes(spec.get("rsrc", b""))
        comment = bytes(spec.get("comment", b""))
        type_code = spec.get("type", b"TEXT")
        creator = spec.get("creator", b"ttxt")
        flags = spec.get("flags", 0)
        file_flags = spec.get("file_flags", 0)
        created = spec.get("created", 400000000)
        modified = spec.get("modified", 400000100)
        finfo = spec.get("finfo")
        if finfo is None:
            finfo = struct.pack(">4s4sH", type_code, creator, flags) \
                + b"\0" * 4 + b"\0\0"
        out.extend(_mar_record(MAR_FILE, _mar_pstr(name_bytes),
                           len(data), len(rsrc), len(comment),
                           file_flags, created, modified, finfo,
                           b"\0" * 4, bad_header_crc))
        out.extend(_mar_block(data, bad_block_crc))
        out.extend(_mar_block(rsrc, bad_block_crc))
        out.extend(_mar_block(comment, bad_block_crc))

    if len(tree["children"]) > 1:
        raise ValueError(
            "a MAR archive holds exactly one item (a file or a folder); "
            "group several items under a folder")
    for child in tree["children"].values():
        emit(child)
    return bytes(out)
