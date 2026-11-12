"""Compact Pro (.cpt) — the container, its RLE, and its LZSS+Huffman.

Layout, from the format's own published description (The Unarchiver's
wiki, three pages) with the corrections the parent project established
by decoding whole forks — written up in its ``docs/formats/
compact-pro.md``:

  File header, 8 bytes: u8 signature (= 1), u8 volume, u16 xmagic,
  u32 offset of the index.

  Index, at ``offset``: u32 index CRC, then the CRC'd region: u16
  nentries, u8 commentlen, comment, then ``nentries`` entry headers.
  The CRC is CRC-32 (reflected 0xEDB88320), seeded 0xFFFFFFFF and
  compared WITHOUT the final xor.  nentries counts every header,
  folders included.

  Entry header: u8 namelen (bit 7 = folder), name (namelen & 0x7f
  bytes); a folder then carries u16 subtree entry count — counting
  every header below it, sub-directories included, which alone
  rebuilds the paths — a file then 45 bytes::

      u8 volume, u32 fileoffs, u32 type, u32 creator, u32 createdate,
      u32 moddate, u16 finderflags, u32 fileCRC, u16 flags,
      u32 rsrclen, u32 datalen, u32 rsrccomplen, u32 datacomplen

  flags: bit 0 = encrypted, bit 1 = resource fork LZH, bit 2 = data
  fork LZH (otherwise the fork is RLE only).

  File data, at absolute ``fileoffs``: the compressed resource fork
  (rsrccomplen bytes) immediately followed by the compressed data
  fork (datacomplen bytes).  fileCRC is CRC-32 — same seeding, no
  final xor — over the decoded resource fork then the decoded data
  fork.

The compression is an ``0x81 0x82`` run filter, optionally preceded
by an LZSS + canonical Huffman stage ("LZH"); the header's lengths
count what the RLE PRODUCES, so the decode stops on them, not on the
LZSS layer.  The coder's details — the count byte in front of each
code list, no Reverse16, the offset taken exactly with 0 legal, no
length base, the block flush rule — are the parent project's
corrections; the state machines here mirror its ``fmt_cpt.c``.

Encryption (flag 0x0001) is Compact Pro's own CRC-table cipher: the
password becomes a nine-byte key folded into a 64-bit CRC register
seeded 0x01234567/0x89ABCDEF; each byte XORs the register's bits
8..15 and then feeds back in on the PLAINTEXT.  An encrypted entry's
stream opens with eight bytes decrypted and discarded, counted in the
first non-empty fork's compressed length, and the cipher runs across
both forks without resetting.  Compact Pro stores nothing that
verifies a password — the entry's CRC-32 is the only evidence — so a
wrong password is only visible after a full decode.

The index lives in the last segment of a set; segmented archives are
refused by name.
"""

import struct
import zlib

from .._core import Archive, Entry
from ..errors import (BadPasswordError, CorruptError, PasswordRequiredError,
                      UnsupportedError)

WINDOW = 8192          # the LZSS window, 1 << 13 (correction 3)
BLOCK = 0x1FFF0        # cost units per Huffman block (2/literal, 3/match)
CRYPT_PREAMBLE = 8     # decrypted and discarded, in the first fork
MAX_DEPTH = 32

_ESC1, _ESC2 = 0x81, 0x82


def _u16(buf, at):
    if at + 2 > len(buf):
        raise CorruptError("Compact Pro: index cut short")
    return struct.unpack_from(">H", buf, at)[0]


def _u32(buf, at):
    if at + 4 > len(buf):
        raise CorruptError("Compact Pro: index cut short")
    return struct.unpack_from(">I", buf, at)[0]


def _crc32_raw(data):
    """The register the format stores: seeded 0xFFFFFFFF, no final xor."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


# ------------------------------------------------------------------ #
# The 0x81 0x82 run filter                                           #
# ------------------------------------------------------------------ #


class _Rle:
    """The run filter as a state machine, driven to exactly ``want``
    output bytes — the length the entry header declares.

    ``0x81 0x82 n>0`` appends n-1 copies of the previous byte,
    ``0x81 0x82 0`` the literal pair, ``0x81 X`` the literal ``0x81``
    then X; an ``0x81`` that would be the LAST output byte is a
    literal (the ``remaining != 1`` tests).
    """

    def __init__(self, want):
        self.want = want
        self.out = bytearray()
        self.state = 0          # 0 none, 1 escape 1 seen, 2 escape 2 seen
        self.saved = 0

    def full(self):
        return len(self.out) >= self.want

    def push(self, b):
        # Every arm may run only when the output is not yet full; the
        # guards inside keep a second append from overshooting `want`.
        if self.state == 0:
            if b == _ESC1 and (self.want - len(self.out)) != 1:
                self.state = 1
            else:
                self.saved = b
                self.out.append(b)
        elif self.state == 1:
            if b == _ESC2:
                self.state = 2
            else:
                self.saved = _ESC1
                self.out.append(_ESC1)
                if self.full():
                    return
                if b == _ESC1 and (self.want - len(self.out)) != 1:
                    return              # stay in state 1, b pending
                self.state = 0
                self.saved = b
                self.out.append(b)
        else:
            self.state = 0
            if b != 0:
                n = min(b - 1, self.want - len(self.out))
                if n:
                    self.out.extend(bytes([self.saved]) * n)
            else:
                self.out.append(_ESC1)
                if self.full():
                    return
                self.saved = _ESC2
                self.out.append(_ESC2)


def rle8182_decode(stored, length):
    """One plain-RLE fork: ``stored`` bytes in, ``length`` out."""
    if length == 0:
        return b""
    rle = _Rle(length)
    for b in stored:
        rle.push(b)
        if rle.full():
            return bytes(rle.out)
    raise CorruptError("Compact Pro: the RLE stream ends before the fork does")


# ------------------------------------------------------------------ #
# LZSS + canonical Huffman, then the run filter                      #
# ------------------------------------------------------------------ #


def _build_codes(lengths):
    """The wiki's construction with its Reverse16 NOT applied: read
    MSB-first, the code is the top ``length`` bits of the accumulator,
    ascending (length, value), at most 15 bits."""
    table = {}
    code = 0
    for length in range(1, 16):
        for i, l in enumerate(lengths):
            if l != length:
                continue
            table[(length, code >> (16 - length))] = i
            code += 1 << (16 - length)
    return table


def _read_code(data, p, nsyms):
    """One code list: a byte count n, then n bytes of two 4-bit code
    lengths each (high nibble first); every length after those 2n is
    zero."""
    if p >= len(data):
        raise CorruptError("Compact Pro: the LZH stream ends early")
    n = data[p]
    p += 1
    if n * 2 > nsyms:
        raise CorruptError("Compact Pro: bad Huffman code length")
    if p + n > len(data):
        raise CorruptError("Compact Pro: the LZH stream ends early")
    lengths = []
    for k in range(n):
        b = data[p + k]
        lengths.append(b >> 4)
        lengths.append(b & 15)
    p += n
    lengths = lengths[:nsyms] + [0] * (nsyms - len(lengths))
    return _build_codes(lengths), p


class _Bits:
    """MSB-first bits from the fork's bytes."""

    def __init__(self, data, bytepos):
        self.data = data
        self.pos = bytepos << 3

    def bit(self):
        if self.pos >> 3 >= len(self.data):
            raise CorruptError("Compact Pro: the LZH stream ends early")
        b = (self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return b

    def bits(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | self.bit()
        return v

    def bytepos(self):
        return self.pos >> 3

    def align(self):
        self.pos = (self.pos + 7) & ~7


def _sym(bits, table):
    code = 0
    for length in range(1, 16):
        code = (code << 1) | bits.bit()
        found = table.get((length, code))
        if found is not None:
            return found
    raise CorruptError("Compact Pro: no Huffman code matches the stream")


def lzh_decode(stored, length):
    """One LZH fork: the LZSS loop over an 8 KB window, its block
    accounting (2 per literal, 3 per match, block at or past
    0x1fff0) and its flush rule (align, then skip three bytes if an
    odd number was consumed since the block's data began, else two),
    each byte fed through the run filter — which is what the header's
    length counts."""
    if length == 0:
        return b""
    win = bytearray(WINDOW)
    wpos = 0
    rle = _Rle(length)
    p = 0
    first = True
    blockstart = 0
    bs = None
    while not rle.full():
        if not first:
            bs.align()
            consumed = bs.bytepos() - blockstart
            p = bs.bytepos() + (3 if consumed & 1 else 2)
        tlit, p = _read_code(stored, p, 256)
        tlen, p = _read_code(stored, p, 64)
        toff, p = _read_code(stored, p, 128)
        first = False
        bs = _Bits(stored, p)
        blockstart = p
        cost = 0
        while cost < BLOCK and not rle.full():
            if bs.bit():
                v = _sym(bs, tlit)
                win[wpos & (WINDOW - 1)] = v
                wpos += 1
                rle.push(v)
                cost += 2
            else:
                mlen = _sym(bs, tlen)
                moff = (_sym(bs, toff) << 6) | bs.bits(6)
                # The copy and the filter are one walk; overlap (and
                # even offset 0, reading bytes as they are written)
                # is legal.  A match may overshoot the header's
                # length; the filter clamps it.
                for _ in range(mlen):
                    if rle.full():
                        break
                    b = win[(wpos - moff) & (WINDOW - 1)]
                    win[wpos & (WINDOW - 1)] = b
                    wpos += 1
                    rle.push(b)
                cost += 3
    return bytes(rle.out)


# ------------------------------------------------------------------ #
# The cipher                                                         #
# ------------------------------------------------------------------ #


def _crc64_table():
    """Eight reflected steps of a 64-bit CRC with 0xEDB88320 in both
    halves, in two 32-bit registers — Compact Pro 1.51's own table,
    as an algorithm."""
    tab = []
    for i in range(256):
        hi = lo = 0
        v = i
        for _ in range(8):
            fb = (lo ^ v) & 1
            lo = (lo >> 1) | ((hi & 1) << 31)
            hi >>= 1
            if fb:
                hi ^= 0xEDB88320
                lo ^= 0xEDB88320
            v >>= 1
        tab.append((hi, lo))
    return tab


class _Cipher:
    """The keystream: keyed from the password, then fed one plaintext
    byte at a time.  Decrypt and encrypt are the same walk — the
    feedback index is the PLAINTEXT either way."""

    def __init__(self, password):
        if isinstance(password, str):
            password = password.encode("latin-1", errors="replace")
        key = [0] * 9
        for i, ch in enumerate(password):
            key[(i & 7) + 1] = (key[(i & 7) + 1] + ch) & 0xFF
        n = min(len(password), 8)
        key[0] = n
        self.tab = _crc64_table()
        hi, lo = 0x01234567, 0x89ABCDEF
        for i in range(1, n + 1):
            idx = key[i] ^ (lo & 0xFF)
            hi, lo = self._step(hi, lo, idx)
        self.hi, self.lo = hi, lo

    def _step(self, hi, lo, idx):
        t_hi, t_lo = self.tab[idx]
        lo = (((hi << 24) | (lo >> 8)) & 0xFFFFFFFF) ^ t_lo
        hi = (hi >> 8) ^ t_hi
        return hi, lo

    def _ks_step(self):
        ks = (self.lo >> 8) & 0xFF
        return ks

    def encrypt(self, data):
        out = bytearray()
        for plain in data:
            ks = self._ks_step()
            self.hi, self.lo = self._step(self.hi, self.lo,
                                          plain ^ (self.lo & 0xFF))
            out.append(plain ^ ks)
        return bytes(out)

    def decrypt(self, data):
        # The feedback index is the PLAINTEXT here too — which is the
        # byte just recovered, not the ciphertext it came from.
        out = bytearray()
        for ciphered in data:
            ks = self._ks_step()
            plain = ciphered ^ ks
            self.hi, self.lo = self._step(self.hi, self.lo,
                                          plain ^ (self.lo & 0xFF))
            out.append(plain)
        return bytes(out)


# ------------------------------------------------------------------ #
# Container                                                          #
# ------------------------------------------------------------------ #


class _FileRec:
    """The 45-byte file header, unpacked."""

    __slots__ = ("volume", "fileoffs", "ftype", "fcreator", "created",
                 "modified", "finderflags", "filecrc", "flags",
                 "rsrclen", "datalen", "rcomp", "dcomp", "name")

    def __init__(self, meta, name):
        (self.volume, self.fileoffs, self.ftype, self.fcreator,
         self.created, self.modified, self.finderflags, self.filecrc,
         self.flags, self.rsrclen, self.datalen, self.rcomp,
         self.dcomp) = struct.unpack_from(">BIIIIIHIHIIII", meta)
        self.name = name


def _walk_index(data, index_off):
    """Read the index in one pass, returning ``(comment, records)`` —
    each record either ``("dir", name_bytes, count)`` or
    ``("file", name_bytes, meta45)``."""
    nentries = _u16(data, index_off + 4)
    commentlen = data[index_off + 6]
    start = index_off + 7
    if start + commentlen > len(data):
        raise CorruptError("Compact Pro: index cut short")
    comment = data[start:start + commentlen]
    p = start + commentlen
    records = []
    for _ in range(nentries):
        if p >= len(data):
            raise CorruptError("Compact Pro: index cut short")
        nl = data[p]
        p += 1
        namelen = nl & 0x7F
        if p + namelen > len(data):
            raise CorruptError("Compact Pro: index cut short")
        name = data[p:p + namelen]
        p += namelen
        if nl & 0x80:
            records.append(("dir", name, _u16(data, p)))
            p += 2
        else:
            if p + 45 > len(data):
                raise CorruptError("Compact Pro: index cut short")
            records.append(("file", name, data[p:p + 45]))
            p += 45
    return comment, records


def _index_region(data, index_off, comment, records):
    """Everything the index CRC covers: nentries and commentlen through
    the last entry header."""
    region = data[index_off + 4:index_off + 7 + len(comment)]
    for kind, name, payload in records:
        nl = len(name) | (0x80 if kind == "dir" else 0)
        region += bytes([nl]) + name
        region += struct.pack(">H", payload) if kind == "dir" else payload
    return region


def probe(data):
    """Signature byte plus the full index CRC walk — a one-byte magic
    is far too weak on its own."""
    if len(data) < 8 or data[0] != 1:
        return 0
    index_off = struct.unpack_from(">I", data, 4)[0]
    if index_off + 7 > len(data):
        return 0
    stored = struct.unpack_from(">I", data, index_off)[0]
    try:
        comment, records = _walk_index(data, index_off)
    except CorruptError:
        return 0
    if _crc32_raw(_index_region(data, index_off, comment, records)) != stored:
        return 0
    return 85


def _decode_forks(data, rec, password):
    """Both forks of one file record, in stored order: resource first,
    then data, with one CRC-32 across the pair."""
    if rec.volume != 1:
        raise UnsupportedError(
            "Compact Pro: %r lives in volume %d; segmented archives are"
            " not supported" % (rec.name, rec.volume))
    if (rec.fileoffs + rec.rcomp + rec.dcomp < rec.fileoffs
            or rec.fileoffs + rec.rcomp + rec.dcomp > len(data)):
        raise CorruptError(
            "Compact Pro: forks of %r point past end of file" % rec.name)
    if rec.flags & 1 and password is None:
        raise PasswordRequiredError(
            "Compact Pro: %r is encrypted; a password is required"
            % rec.name)
    cipher = _Cipher(password) if rec.flags & 1 else None
    # The eight-byte preamble belongs to the first fork with any
    # bytes at all, counted in its compressed length.
    pending_preamble = cipher is not None

    def fork(at, complen, outlen, lzh):
        nonlocal pending_preamble
        if complen == 0 or outlen == 0:
            # macutils returns before writing anything when the
            # compressed fork is empty, whatever the claimed size.
            return b""
        stored = data[at:at + complen]
        if len(stored) != complen:
            raise CorruptError(
                "Compact Pro: fork of %r runs past end of file" % rec.name)
        if cipher is not None:
            stored = cipher.decrypt(stored)
            if pending_preamble:
                pending_preamble = False
                stored = stored[CRYPT_PREAMBLE:]
        if lzh:
            return lzh_decode(stored, outlen)
        return rle8182_decode(stored, outlen)

    rsrc = fork(rec.fileoffs, rec.rcomp, rec.rsrclen, bool(rec.flags & 2))
    data_fork = fork(rec.fileoffs + rec.rcomp, rec.dcomp, rec.datalen,
                     bool(rec.flags & 4))
    if _crc32_raw(rsrc + data_fork) != rec.filecrc:
        if cipher is not None:
            raise BadPasswordError(
                "Compact Pro: incorrect password for %r" % rec.name)
        raise CorruptError("Compact Pro: CRC mismatch for %r" % rec.name)
    return rsrc, data_fork


def _parse(data, password=None):
    if len(data) < 8 or data[0] != 1:
        raise CorruptError("Compact Pro: not a Compact Pro archive")
    index_off = struct.unpack_from(">I", data, 4)[0]
    if index_off + 7 > len(data):
        raise CorruptError("Compact Pro: index offset past end of file")
    stored = struct.unpack_from(">I", data, index_off)[0]
    comment, records = _walk_index(data, index_off)
    if _crc32_raw(_index_region(data, index_off, comment, records)) != stored:
        raise CorruptError("Compact Pro: index CRC mismatch")

    archive = Archive()
    archive.format = "Compact Pro"
    archive.comment = comment

    # The directory-count scheme rebuilds paths: every folder carries
    # the number of headers below it, sub-directories included, and
    # every header decrements its whole stack of budgets — so a stack
    # of (path, entries left) is the walk.
    budgets = [len(records)]
    paths = [""]
    for kind, name, payload in records:
        while len(budgets) > 1 and budgets[-1] == 0:
            budgets.pop()
            paths.pop()
        if budgets[-1] == 0:
            break                       # top level exhausted; CRC gated this
        for i in range(len(budgets)):
            budgets[i] -= 1
        try:
            leaf = name.decode("mac_roman")
        except UnicodeDecodeError:
            leaf = name.decode("mac_roman", errors="replace")
        path = paths[-1] + "/" + leaf if paths[-1] else leaf
        if kind == "dir":
            if payload > budgets[-1]:
                raise CorruptError(
                    "Compact Pro: folder subtree bigger than its parent")
            if len(budgets) >= MAX_DEPTH:
                raise CorruptError("Compact Pro: folders nested too deep")
            budgets.append(payload)
            paths.append(path)
        else:
            rec = _FileRec(payload, path)
            rsrc, data_fork = _decode_forks(data, rec, password)
            archive.entries.append(Entry(
                name=path,
                type=struct.pack(">I", rec.ftype),
                creator=struct.pack(">I", rec.fcreator),
                finder_flags=rec.finderflags,
                created=rec.created,
                modified=rec.modified,
                data_size=rec.datalen,
                resource_size=rec.rsrclen,
                _data=data_fork,
                _rsrc=rsrc,
            ))
    return archive


def open_data(data, password=None, filename=None):
    return _parse(data, password=password)
