"""tar reader tests. Fixtures are generated in memory with the
stdlib ``tarfile`` module (the black-box oracle for the supported
subset) plus hand-built blocks for checksums, overrides and refusals."""

import io
import struct

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract._core import MAC_EPOCH_OFFSET
from macextract.formats import tar as tarmod

import tarfile as stdlib_tarfile


def _make_tar(members, fmt=stdlib_tarfile.USTAR_FORMAT):
    """members: list of (name, data) pairs (regular files)."""
    buf = io.BytesIO()
    with stdlib_tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, payload in members:
            info = stdlib_tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 1700000000
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _open(blob):
    return macextract.open(io.BytesIO(blob))


def test_ustar_round_trip():
    blob = _make_tar([("dir/hello.txt", b"hello tar " * 100),
                      ("plain.txt", b"plain")])
    archive = _open(blob)
    assert archive.format == "tar"
    names = [entry.name for entry in archive.entries]
    assert names == ["dir/hello.txt", "plain.txt"]
    assert archive.read(archive.entries[0], "data") == b"hello tar " * 100


def test_v7_header_reads():
    # v7 has no magic and no prefix: build one by hand (the stdlib
    # only writes ustar and later).
    payload = b"v7 payload"
    header = _ustar_header(b"v7.txt", declared_size=len(payload),
                           mtime=1700000000, magic=False)
    blob = header + payload + b"\0" * (_pad(len(payload)) - len(payload))
    blob += b"\0" * 1024
    archive = _open(blob)
    assert archive.entries[0].name == "v7.txt"
    assert archive.read(archive.entries[0], "data") == payload


def test_pax_long_name_reads():
    longname = "dir/" + "a" * 120 + "/file.txt"
    blob = _make_tar([(longname, b"long name payload")],
                     fmt=stdlib_tarfile.PAX_FORMAT)
    archive = _open(blob)
    assert archive.entries[0].name == longname
    assert archive.read(archive.entries[0], "data") == b"long name payload"


def test_gnu_longname_reads():
    longname = "d/" + "b" * 120 + ".txt"
    blob = _make_tar([(longname, b"gnu longname")],
                     fmt=stdlib_tarfile.GNU_FORMAT)
    archive = _open(blob)
    assert archive.entries[0].name == longname


def test_gnu_longlink_is_consumed(tmp_path):
    # A symlink with a link target past 100 bytes gets a K record; we
    # skip links, but the stream must stay in sync for what follows.
    buf = io.BytesIO()
    with stdlib_tarfile.open(fileobj=buf, mode="w",
                             format=stdlib_tarfile.GNU_FORMAT) as tf:
        target = "t/" + "x" * 120
        info = stdlib_tarfile.TarInfo("link")
        info.type = stdlib_tarfile.SYMTYPE
        info.linkname = target
        tf.addfile(info)
        payload = b"after the link"
        info2 = stdlib_tarfile.TarInfo("after.txt")
        info2.size = len(payload)
        tf.addfile(info2, io.BytesIO(payload))
    archive = _open(buf.getvalue())
    assert [e.name for e in archive.entries] == ["after.txt"]
    assert archive.read(archive.entries[0], "data") == b"after the link"


def test_symlink_and_hardlink_skipped():
    buf = io.BytesIO()
    with stdlib_tarfile.open(fileobj=buf, mode="w") as tf:
        for name, symtype in (("rel", stdlib_tarfile.SYMTYPE),
                              ("hard", stdlib_tarfile.LNKTYPE)):
            info = stdlib_tarfile.TarInfo(name)
            info.type = symtype
            info.linkname = "../escape"
            tf.addfile(info)
        payload = b"real file"
        info = stdlib_tarfile.TarInfo("real.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    archive = _open(buf.getvalue())
    assert [e.name for e in archive.entries] == ["real.txt"]


def test_device_and_fifo_skipped():
    buf = io.BytesIO()
    with stdlib_tarfile.open(fileobj=buf, mode="w") as tf:
        for name, ttype in (("chr", stdlib_tarfile.CHRTYPE),
                            ("blk", stdlib_tarfile.BLKTYPE),
                            ("fifo", stdlib_tarfile.FIFOTYPE)):
            info = stdlib_tarfile.TarInfo(name)
            info.type = ttype
            tf.addfile(info)
        payload = b"devices skipped"
        info = stdlib_tarfile.TarInfo("keep.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    archive = _open(buf.getvalue())
    assert [e.name for e in archive.entries] == ["keep.txt"]


def test_directory_entries_skipped():
    buf = io.BytesIO()
    with stdlib_tarfile.open(fileobj=buf, mode="w") as tf:
        info = stdlib_tarfile.TarInfo("adir")
        info.type = stdlib_tarfile.DIRTYPE
        tf.addfile(info)
        payload = b"inside dir"
        info = stdlib_tarfile.TarInfo("adir/file.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    archive = _open(buf.getvalue())
    assert [e.name for e in archive.entries] == ["adir/file.txt"]


def test_extract_creates_directories(tmp_path):
    blob = _make_tar([("a/b/c.txt", b"deep path")])
    archive = _open(blob)
    out = tmp_path / "out"
    archive.extract(out)
    assert (out / "a" / "b" / "c.txt").read_bytes() == b"deep path"


def test_mtime_converted_to_mac_epoch():
    blob = _make_tar([("stamp.txt", b"stamped")])
    archive = _open(blob)
    assert archive.entries[0].modified == 1700000000 + MAC_EPOCH_OFFSET


def test_checksum_mismatch_refused():
    blob = bytearray(_make_tar([("bad.txt", b"checksum me")]))
    blob[0] ^= 0xFF                 # name byte inside the header
    with pytest.raises(CorruptError, match="checksum"):
        _open(bytes(blob))


def test_truncated_data_refused():
    blob = _make_tar([("big.txt", b"x" * 10000)])
    # cut inside the member's data blocks, not the end padding
    with pytest.raises(CorruptError):
        _open(blob[:512 + 5000])


def test_trailing_junk_after_end_marker_refused():
    blob = _make_tar([("ok.txt", b"fine")]) + b"junk" * 200
    with pytest.raises(CorruptError, match="junk after"):
        _open(blob)


def test_empty_archive_ok():
    blob = _make_tar([])
    archive = _open(blob)
    assert archive.entries == []


def test_non_octal_size_refused():
    blob = bytearray(_make_tar([("octal.txt", b"octal")]))
    blob[124:136] = b"zzzzzzzz\0\0\0\0"
    _fix_checksum(blob, 0)
    with pytest.raises(CorruptError, match="octal"):
        _open(bytes(blob))


def _fix_checksum(blob, offset):
    block = bytearray(blob[offset:offset + 512])
    block[148:156] = b"        "
    total = sum(block)
    blob[offset + 148:offset + 156] = \
        ("%06o\0 " % total).encode("ascii")


def test_pax_size_override_honored():
    # Hand-build: the ustar header says size 10, the pax record before
    # it overrides size to the real payload length.  The reader must
    # serve the pax size.
    payload = b"pax says this is the payload"
    assert len(payload) > 10
    size_record = _pax_record(b"size", str(len(payload)).encode())
    pax_header = _ustar_header(b"PaxHeaders/x", declared_size=len(size_record),
                               mtime=1700000000, typeflag=b"x")
    member = _ustar_header(b"override.txt", declared_size=10,
                           mtime=1700000000, typeflag=b"0")
    blob = pax_header + size_record
    blob += b"\0" * (_pad(len(size_record)) - len(size_record))
    blob += member + payload
    blob += b"\0" * (_pad(len(payload)) - len(payload))
    blob += b"\0" * 1024              # end-of-archive zero blocks
    archive = _open(blob)
    assert archive.read(archive.entries[0], "data") == payload


def _pad(size):
    return (size + 511) & ~511


def _ustar_header(name, declared_size, mtime, typeflag=b"0", magic=True):
    block = bytearray(512)
    encoded = name if isinstance(name, bytes) else name.encode()
    block[0:100] = encoded.ljust(100, b"\0")
    block[100:108] = b"0000644\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    block[124:136] = ("%011o\0" % declared_size).encode()
    block[136:148] = ("%011o\0" % mtime).encode()
    block[148:156] = b"        "
    block[156:157] = typeflag
    if magic:
        block[257:263] = b"ustar\0"
        block[263:265] = b"00"
    total = sum(block)
    block[148:156] = ("%06o\0 " % total).encode()
    return bytes(block)


def _pax_record(key, value):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while True:
        total = len(body) + len(str(length)) + 1
        if total == length:
            return str(length).encode() + b" " + body
        length = total


def test_gnu_sparse_refused():
    buf = io.BytesIO()
    with stdlib_tarfile.open(fileobj=buf, mode="w",
                             format=stdlib_tarfile.GNU_FORMAT) as tf:
        info = stdlib_tarfile.TarInfo("sparse.bin")
        info.type = b"S"
        info.size = 0
        tf.addfile(info)
    with pytest.raises(UnsupportedError, match="sparse"):
        _open(buf.getvalue())


def test_unknown_typeflag_refused():
    blob = _ustar_header(b"mystery", declared_size=0, mtime=1700000000,
                         typeflag=b"Q") + b"\0" * 1024
    with pytest.raises(UnsupportedError, match="typeflag"):
        _open(blob)


def test_ustar_prefix_used():
    buf = io.BytesIO()
    with stdlib_tarfile.open(fileobj=buf, mode="w",
                             format=stdlib_tarfile.USTAR_FORMAT) as tf:
        prefix = "p/" * 60                     # 120 chars
        name = "leaf.txt"
        info = stdlib_tarfile.TarInfo(prefix + name)
        payload = b"prefix file"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    archive = _open(buf.getvalue())
    assert archive.entries[0].name == "p/" * 60 + "leaf.txt"


def test_pax_wrong_size_record_refused():
    bogus = b"99 bogus\n"
    pax_header = _ustar_header(b"PaxHeaders/x", declared_size=len(bogus),
                               mtime=1700000000, typeflag=b"x")
    member = _ustar_header(b"after.txt", declared_size=0, mtime=1700000000)
    blob = pax_header + bogus + b"\0" * (_pad(len(bogus)) - len(bogus))
    blob += member + b"\0" * 1024
    with pytest.raises(CorruptError):
        _open(blob)


def test_extract_sanitises_parent_names(tmp_path):
    blob = _ustar_header(b"../../evil.txt", declared_size=3,
                         mtime=1700000000) + b"abc" + b"\0" * 509
    blob += b"\0" * 1024
    archive = _open(blob)
    out = tmp_path / "out"
    archive.extract(out)
    assert (out / "evil.txt").read_bytes() == b"abc"


def test_probe():
    blob = _make_tar([("probe.txt", b"probe")])
    assert tarmod.probe(blob) > 0
    assert tarmod.probe(b"") == 0
    bad = bytearray(_make_tar([("probe.txt", b"probe")]))
    bad[148:156] = b"99999999"
    # a broken checksum is still claimed so open() can raise CorruptError
    assert tarmod.probe(bytes(bad)) > 0
    garbage = bytearray(512)
    garbage[0] = 1                    # no magic, checksum can't validate
    assert tarmod.probe(bytes(garbage)) == 0


def test_blackbox_oracle_agrees():
    """stdlib tarfile is the oracle: members and bytes match."""
    members = [("one.txt", b"first"), ("dir/two.txt", b"second " * 500),
               ("deep/a/b/c/d.bin", bytes(range(256)) * 10)]
    blob = _make_tar(members)
    archive = _open(blob)
    with stdlib_tarfile.open(fileobj=io.BytesIO(blob), mode="r") as tf:
        orated = [(m.name, tf.extractfile(m).read())
                  for m in tf.getmembers() if m.isfile()]
    assert [(e.name, archive.read(e, "data"))
            for e in archive.entries] == orated
