"""tar reader — ustar (POSIX.1-1988), v7 and pax (POSIX.1-2001).

Record layout (512-byte blocks, data follows each header, padded
with NULs to a block boundary)::

       0 100  name
     100   8  mode (octal)
     108   8  uid (octal)
     116   8  gid (octal)
     124  12  size (octal, or base-256 if the first byte has 0x80 set)
     136  12  mtime (octal, or base-256; seconds since the Unix epoch)
     148   8  chksum — sum of the 512 bytes with this field treated
              as spaces, stored as octal (a leading digit, NULs/spaces)
     156   1  typeflag
     157 100  linkname
     257   6  magic — b"ustar\\0" (ustar/pax), b"ustar  " style for
              GNU, empty for v7
     257   8  magic + version for ustar ("ustar\\0" + "00")
     265  32  uname
     297  32  gname
     329   8  devmajor
     337   8  devminor
     345 155  prefix (ustar) — the name is prefix + "/" + name

End of archive: two consecutive zero blocks.  A single zero block, or
a clean EOF on a block boundary, also ends the stream; non-zero junk
after the marker is an error.

What is carried as entries: regular files and contiguous files
(typeflag ``0``, ``\\0``, ``7``).  Directories, symlinks, hard links,
device nodes, fifos and anything else are **skipped, not followed** —
a tar can name a member ``../..`` or point a link at ``/etc/passwd``;
none of that may escape through an extract.  Directory entries are
skipped because the extract path creates directories implicitly.
Skipped members are listed kinds only; an unknown typeflag is treated
as unsupported by name (UnsupportedError), not silently dropped.

pax extended headers (typeflag ``x``, per-member, and ``g``, global):
records of the form ``<len> <key>=<value>\\n`` where ``<len>``
counts itself.  ``path``, ``linkpath``, ``size`` and ``mtime`` are
consumed and applied to the following member; everything else
(including ``SCHILY.*`` / ``LIBARCHIVE.*`` xattrs) is skipped.  pax
is what makes long names and sizes past octal's 8 GiB ceiling work.

GNU tar's own long-name records (typeflag ``L`` for the name, ``K``
for the link target, ``S`` for sparse files, ``V`` for volume
headers): ``L`` and ``K`` are consumed and applied the same way;
``S`` is refused by name; ``V`` is consumed and ignored.
"""

from .._core import MAC_EPOCH_OFFSET, Archive, Entry
from ..errors import CorruptError, UnsupportedError

BLOCK = 512
ZERO_BLOCKS = 2

TYPE_REG = b"0"
TYPE_REG_NUL = b"\0"
TYPE_CONTIG = b"7"
TYPE_DIR = b"5"
TYPE_HARDLINK = b"1"
TYPE_SYMLINK = b"2"
TYPE_CHARDEV = b"3"
TYPE_BLOCKDEV = b"4"
TYPE_FIFO = b"6"
TYPE_GNU_LONGLINK = b"K"
TYPE_GNU_LONGNAME = b"L"
TYPE_GNU_SPARSE = b"S"
TYPE_GNU_VOLHDR = b"V"
TYPE_PAX_GLOBAL = b"g"
TYPE_PAX_EXT = b"x"

_SKIPPED = {TYPE_DIR, TYPE_HARDLINK, TYPE_SYMLINK, TYPE_CHARDEV,
            TYPE_BLOCKDEV, TYPE_FIFO}

_NAME_KEYS = ("path",)


def _parse_number(field, what, base256_ok=True):
    if base256_ok and field and field[0] & 0x80:
        # GNU base-256: the high bit marks the encoding; the rest is
        # big-endian binary.  Sizes are never negative here.
        return int.from_bytes(bytes([field[0] & 0x7F]) + field[1:], "big")
    text = field.split(b"\0", 1)[0].strip()
    if not text:
        return 0
    try:
        value = int(text, 8)
    except ValueError as error:
        raise CorruptError("tar: %s is not octal (%r)" % (what, field)) from error
    return value


def _header_checksum_ok(block):
    try:
        stored = _parse_number(block[148:156], "chksum")
    except CorruptError:
        return False
    unsigned = sum(block[:148]) + 8 * 0x20 + sum(block[156:])
    if unsigned == stored:
        return True
    signed = sum(b - 256 if b > 127 else b for b in block[:148]) \
        + 8 * 0x20 \
        + sum(b - 256 if b > 127 else b for b in block[156:])
    return signed == stored


def probe(data):
    if len(data) < BLOCK:
        return 0
    block = data[:BLOCK]
    if block[257:262] == b"ustar":
        # Claim even a broken checksum: ``open`` then surfaces the
        # checksum CorruptError instead of "unrecognised archive".
        return 90 if _header_checksum_ok(block) else 50
    if not any(block):
        return 25           # all-zero first block: an empty tar, yield nothing
    return 40 if _header_checksum_ok(block) else 0


def _split_nul(field):
    return field.split(b"\0", 1)[0]


def _pax_replacements(records, number):
    """Parse pax extended-header records; return overrides."""
    overrides = {}
    offset = 0
    while offset < len(records):
        space = records.find(b" ", offset)
        if space == -1:
            raise CorruptError(
                "tar: pax record %d has no length separator" % number)
        try:
            length = int(records[offset:space], 10)
        except ValueError as error:
            raise CorruptError(
                "tar: pax record %d has a non-decimal length" % number) from error
        if length <= 0 or offset + length > len(records):
            raise CorruptError(
                "tar: pax record %d declares length %d past the record"
                " block" % (number, length))
        record = records[space + 1:offset + length]
        if not record.endswith(b"\n"):
            raise CorruptError(
                "tar: pax record %d does not end with a newline" % number)
        body = record[:-1]
        equals = body.find(b"=")
        if equals == -1:
            raise CorruptError(
                "tar: pax record %d has no '=' separator" % number)
        key = body[:equals].decode("utf-8", errors="replace")
        value = body[equals + 1:]
        if key == "path":
            overrides["name"] = value.decode("utf-8", errors="surrogateescape")
        elif key == "linkpath":
            overrides["linkpath"] = value.decode("utf-8",
                                                 errors="surrogateescape")
        elif key == "size":
            try:
                overrides["size"] = int(value, 10)
            except ValueError as error:
                raise CorruptError(
                    "tar: pax record %d has a non-decimal size" % number) from error
        elif key == "mtime":
            try:
                overrides["mtime"] = float(value)
            except ValueError as error:
                raise CorruptError(
                    "tar: pax record %d has a non-decimal mtime" % number) from error
        offset += length
    return overrides


def _data_blocks(size):
    return (size + BLOCK - 1) // BLOCK


def open_data(data, password=None, filename=None):
    if password is not None:
        raise UnsupportedError("tar: tar archives are not encrypted")

    archive = Archive()
    archive.format = "tar"

    offset = 0
    pending = {}          # overrides for the next member (pax/GNU)
    number = 0            # member index, for diagnostics
    while True:
        remaining = len(data) - offset
        if remaining == 0:
            break
        if remaining < BLOCK:
            tail = data[offset:]
            if not any(tail):
                break     # ragged zero padding at EOF; tolerate
            raise CorruptError(
                "tar: %d trailing bytes at offset %d where a 512-byte"
                " header block was expected" % (remaining, offset))
        block = data[offset:offset + BLOCK]
        if not any(block):
            if any(data[offset + BLOCK:]):
                raise CorruptError(
                    "tar: non-zero junk after the end-of-archive marker"
                    " at offset %d" % offset)
            break         # zero block: end of archive
        if not _header_checksum_ok(block):
            raise CorruptError(
                "tar: header block at offset %d fails its checksum"
                % offset)

        raw_name = _split_nul(block[0:100])
        raw_prefix = _split_nul(block[345:500])
        magic = block[257:265]
        is_ustar = magic.startswith(b"ustar")
        if is_ustar and raw_prefix:
            raw_name = raw_prefix + b"/" + raw_name
        name = raw_name.decode("utf-8", errors="surrogateescape")

        size = _parse_number(block[124:136], "size")
        mtime = _parse_number(block[136:148], "mtime",
                              base256_ok=True)
        typeflag = block[156:157]
        header_end = offset + BLOCK
        data_end = header_end + size
        if data_end > len(data):
            raise CorruptError(
                "tar: member %r at offset %d declares %d bytes of data,"
                " which runs past end of file" % (name, offset, size))
        body = data[header_end:data_end]
        next_offset = header_end + _data_blocks(size) * BLOCK
        if next_offset > len(data):
            raise CorruptError(
                "tar: member %r at offset %d is truncated"
                % (name, offset))

        if typeflag == TYPE_PAX_EXT or typeflag == TYPE_PAX_GLOBAL:
            overrides = _pax_replacements(bytes(body), number + 1)
            if typeflag == TYPE_PAX_EXT:
                pending.update(overrides)
            offset = next_offset
            number += 1
            continue
        if typeflag == TYPE_GNU_LONGNAME:
            pending["name"] = _split_nul(body).decode(
                "utf-8", errors="surrogateescape")
            offset = next_offset
            number += 1
            continue
        if typeflag == TYPE_GNU_LONGLINK:
            offset = next_offset
            number += 1
            continue
        if typeflag == TYPE_GNU_SPARSE:
            raise UnsupportedError(
                "tar: member %r is a GNU sparse file, which is not"
                " supported yet" % name)
        if typeflag == TYPE_GNU_VOLHDR:
            offset = next_offset
            number += 1
            continue

        if pending:
            name = pending.get("name", name)
            if "size" in pending:
                size = pending["size"]
                data_end = header_end + size
                if data_end > len(data):
                    raise CorruptError(
                        "tar: member %r at offset %d declares %d bytes of"
                        " data (pax), which runs past end of file"
                        % (name, offset, size))
                body = data[header_end:data_end]
                next_offset = header_end + _data_blocks(size) * BLOCK
                if next_offset > len(data):
                    raise CorruptError(
                        "tar: member %r at offset %d is truncated"
                        % (name, offset))
            if "mtime" in pending:
                mtime = int(pending["mtime"])
            pending = {}

        if typeflag in _SKIPPED:
            # Directory, symlink, hard link, device node or fifo:
            # never followed, never extracted; the extract path builds
            # directories from the file entries themselves.
            offset = next_offset
            number += 1
            continue
        if typeflag not in (TYPE_REG, TYPE_REG_NUL, TYPE_CONTIG):
            raise UnsupportedError(
                "tar: member %r has typeflag %r, which is not supported"
                % (name, typeflag))

        modified = mtime + MAC_EPOCH_OFFSET
        entry = Entry(name=name,
                      modified=modified,
                      created=modified,
                      data_size=size,
                      resource_size=0,
                      _data=bytes(body),
                      _rsrc=b"")
        archive.entries.append(entry)
        offset = next_offset
        number += 1
    return archive
