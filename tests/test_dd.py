import io
import struct

import pytest

import macextract
from macextract import CorruptError, MacExtractError, UnsupportedError
from macextract.formats import dd as ddmod

import macarchives

DATA = b"DiskDoubler payload, repeated repeated repeated " * 8
RSRC = b"\x00\x01\x81\x82 rsrc with escapes " * 4


def _open(image, password=None, filename=None):
    if filename is None:
        return macextract.open(io.BytesIO(image), password=password)
    return macextract.open(image, password=password)


# --- Both coders, every method, and the delta form -------------------

@pytest.mark.parametrize("method", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
@pytest.mark.parametrize("delta", [False, True])
def test_every_method_round_trips(method, delta, tmp_path):
    if method == 8 and delta:
        pytest.skip("method 8 has no delta form")
    image = macarchives.dd_single("Smoke", DATA, data_method=method,
                                  delta=delta)
    path = tmp_path / "Smoke.bin.dd"
    path.write_bytes(image)
    archive = macextract.open(path)
    assert archive.format == "DiskDoubler"
    assert archive.entries[0].name == "Smoke.bin"
    assert archive.read(archive.entries[0], "data") == DATA


@pytest.mark.parametrize("method", [1, 2, 5])
def test_garbled_methods_round_trip(method):
    image = macarchives.dd_single("Garb", DATA, data_method=method,
                                  garble=True)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_1990_48_byte_header_opens():
    image = macarchives.dd_single("Old", DATA, variant=48)
    assert ddmod.probe(image) == 85
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_1990_48_byte_header_ignores_absent_checksums(tmp_path):
    # The 1990 file states no checksums; a zero checksum is "not kept".
    image = bytearray(macarchives.dd_single("Old", DATA, variant=48))
    image[60] ^= 0xFF        # inside the stored fork (past the 48 bytes)
    path = tmp_path / "Old.dd"
    path.write_bytes(bytes(image))
    archive = macextract.open(path)
    assert archive.read(archive.entries[0], "data") != DATA


def test_method_8_lzh_branch_round_trips():
    image = macarchives.dd_single("Lzh", DATA, data_method=8, lzh=True)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_delta_distance_two_is_refused_by_name():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=10))
    struct.pack_into(">H", image, 54, 2)      # the data fork's delta distance
    with pytest.raises(UnsupportedError, match="delta distance 2"):
        ddmod.open_data(bytes(image))


def test_method_8_with_delta_is_refused_by_name():
    # The delta transform cannot sit outside Compact Pro's coder.
    image = bytearray(macarchives.dd_single("D", DATA, data_method=8))
    image[20] |= 0x80                         # the data fork's method byte
    struct.pack_into(">H", image, 54, 1)
    with pytest.raises(UnsupportedError, match="method 8 with a delta"):
        ddmod.open_data(bytes(image))


def test_an_unsupported_method_is_refused_by_name():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=0))
    image[20] = 11
    with pytest.raises(UnsupportedError, match="method 11"):
        ddmod.open_data(bytes(image))


def test_method_5_with_a_non_power_of_two_context_count_is_refused():
    with pytest.raises(UnsupportedError, match="non-power-of-two"):
        _open(macarchives.dd_single("D", DATA, data_method=5, count=3))


# --- The containers ---------------------------------------------------

def _ddar_entries():
    DATA_LOCAL = DATA
    return [
        {"path": "Top.txt", "data": DATA_LOCAL, "method": 10},
        {"path": "Docs/Inside.bin", "data": DATA_LOCAL.upper(),
         "method": 2, "delta": True, "garble": True},
        {"path": "Docs/Sub/Deep.cpt", "data": DATA_LOCAL, "method": 7},
        {"path": "Docs/Raw.txt", "data": DATA_LOCAL, "raw": True},
        {"path": "Docs/Rsrc.bin", "data": DATA_LOCAL, "rsrc": RSRC,
         "method": 4},
    ]


def _dda2_entries():
    return _ddar_entries()


@pytest.mark.parametrize("builder,formats", [
    (macarchives.ddar, "DiskDoubler (DDAR)"),
    (macarchives.dda2, "DiskDoubler Pro (DDA2)"),
])
def test_container_lists_and_reads(builder, formats):
    image = builder(_ddar_entries())
    archive = _open(image)
    assert archive.format == formats
    expected = {
        "Top.txt": DATA,
        "Docs/Inside.bin": DATA.upper(),
        "Docs/Sub/Deep.cpt": DATA,
        "Docs/Raw.txt": DATA,
        "Docs/Rsrc.bin": DATA,
    }
    assert {e.name: archive.read(e, "data")
            for e in archive.entries} == expected
    rsrc = next(e for e in archive.entries if e.name == "Docs/Rsrc.bin")
    assert archive.read(rsrc, "rsrc") == RSRC


@pytest.mark.parametrize("builder", [macarchives.ddar, macarchives.dda2])
def test_container_rebuilds_paths_with_duplicate_leaves(builder):
    image = builder([
        {"path": "One/Same", "data": b"first", "method": 0},
        {"path": "Two/Same", "data": b"second", "method": 0},
        {"path": "Same", "data": b"third", "method": 0},
    ])
    archive = _open(image)
    assert [e.name for e in archive.entries] == [
        "One/Same", "Two/Same", "Same"]
    assert [archive.read(e, "data") for e in archive.entries] == [
        b"first", b"second", b"third"]


@pytest.mark.parametrize("builder", [macarchives.ddar, macarchives.dda2])
def test_container_probe_recognises_it(builder):
    image = builder([{"path": "A", "data": b"x"}])
    assert ddmod.probe(image) >= 60
    assert ddmod.probe(image[:40]) == 0
    assert ddmod.probe(b"not an archive at all") == 0


@pytest.mark.parametrize("trailer", [True, False])
def test_ddar_file_header_span_with_and_without_trailer(trailer):
    image = macarchives.ddar([{"path": "A", "data": DATA, "method": 0}],
                             trailer=trailer)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


@pytest.mark.parametrize("trailer", [True, False])
def test_dda2_file_header_with_and_without_trailer(trailer):
    image = macarchives.dda2([{"path": "A", "data": DATA, "method": 0}],
                             trailer=trailer)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_dda2_markerless_end_between_records_and_at_eof():
    image = macarchives.dda2([{"path": "A", "data": DATA, "method": 0}],
                             markerless=True)
    assert _open(image).entries[0].name == "A"
    image = macarchives.dda2([{"path": "A", "data": DATA, "method": 0}],
                             markerless=True, junk_end=38)
    assert _open(image).entries[0].name == "A"


def test_dda2_without_end_marker_or_leftover_bytes_is_corrupt():
    entries = [{"path": "A", "data": DATA, "method": 0}]
    image = bytearray(macarchives.dda2(entries, markerless=True))
    # Chop 50 bytes: nothing left to mistake for the marker-less end.
    del image[-50:]
    with pytest.raises(CorruptError):
        ddmod.open_data(bytes(image))


def test_dda2_a_record_running_past_the_end_is_corrupt():
    image = bytearray(macarchives.dda2(
        [{"path": "A", "data": DATA, "method": 0}]))
    struct.pack_into(">I", image, 62 + 42, 0x7FFFFF00)
    with pytest.raises(CorruptError, match="past end of file"):
        ddmod.open_data(bytes(image))


def test_ddar_a_record_running_past_the_end_is_corrupt():
    image = bytearray(macarchives.ddar(
        [{"path": "A", "data": DATA, "method": 0}]))
    struct.pack_into(">I", image, 78 + 74, 0x7FFFFFFF)   # the record's span
    struct.pack_into(">I", image, 78 + 78, 0)
    with pytest.raises(CorruptError):
        _open(bytes(image))


def test_ddar_a_header_magic_where_a_record_should_be_is_corrupt():
    image = bytearray(macarchives.ddar(
        [{"path": "A", "data": DATA, "method": 0}]))
    image[78] ^= 0xFF
    with pytest.raises(CorruptError, match="magic not where expected"):
        ddmod.open_data(bytes(image))


@pytest.mark.parametrize("builder", [macarchives.ddar, macarchives.dda2])
def test_an_empty_container_lists_nothing(builder):
    assert _open(builder([])).entries == []


# --- Corruption -------------------------------------------------------

def test_a_bad_16_bit_sum_is_corrupt():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=3))
    data_method_at = 20
    assert image[data_method_at] == 3
    image[20 + 84 + 10] ^= 0x40     # inside the coded fork
    with pytest.raises(CorruptError, match="16-bit sum"):
        ddmod.open_data(bytes(image))


def test_a_bad_block_xor_in_an_ad_block_is_corrupt():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=6))
    image[84] ^= 0x10               # inside the first block header
    with pytest.raises(CorruptError, match="block header XOR"):
        ddmod.open_data(bytes(image))


def test_a_bad_block_xor_in_a_ddn_block_is_corrupt():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=10))
    image[84 + 3] ^= 0x10           # inside the block header
    with pytest.raises(CorruptError):
        ddmod.open_data(bytes(image))


def test_a_bad_stac_checksum_is_corrupt():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=7))
    image[49] ^= 0x01               # the data fork's stored checksum low byte
    with pytest.raises(CorruptError, match="XOR checksum"):
        ddmod.open_data(bytes(image))


def test_a_bad_method_8_crc_is_corrupt():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=8))
    image[48] ^= 0xFF               # the data fork's stored CRC-16
    with pytest.raises(CorruptError, match="CRC-16/ARC"):
        ddmod.open_data(bytes(image))


def test_a_truncated_single_file_is_corrupt():
    image = macarchives.dd_single("D", DATA, data_method=0)
    with pytest.raises(MacExtractError):
        _open(image[:len(image) // 2])


def test_a_damaged_fork_falls_through_the_sniffer():
    image = bytearray(macarchives.dd_single("D", DATA, data_method=0))
    image[0] = 0x00                 # the magic is gone
    with pytest.raises(MacExtractError):
        _open(bytes(image))


def test_finder_info_is_carried_for_a_single_file():
    image = macarchives.dd_single("D", DATA, type=b"TEXT",
                                  creator=b"TLst", flags=0x0100)
    entry = _open(image).entries[0]
    assert entry.finder_info is not None
    assert entry.finder_info[0:4] == b"TEXT"
    assert entry.finder_info[4:8] == b"TLst"
    assert entry.finder_info[8:10] == b"\x01\x00"


def test_extract_writes_both_forks(tmp_path):
    image = macarchives.dd_single("D", DATA, rsrc=RSRC, data_method=0)
    path = tmp_path / "D.bin.dd"
    path.write_bytes(image)
    archive = macextract.open(path)
    written = archive.extract(str(tmp_path / "out"))
    assert (tmp_path / "out" / "D.bin").read_bytes() == DATA
    dot = tmp_path / "out" / "._D.bin"
    assert dot.exists()
    assert len(written) == 2


# --- DDn: a hand-built block with a match and a run ------------------

def _ddn_offset_section():
    # Four symbols, symbol 3 at length 1 (slot 3, offset 4, no extra
    # bits).  Returns the 6-byte section: head, one byte of code
    # lengths, then the value stream (the one-bit code 0).
    head = 0x03002108        # numcodes 4, numbytes 1, maxlen 1, numbits 1
    return struct.pack(">I", head) + b"\x10" + b"\x00"


def _ddn_length_code_section(symbols_with_two_bits):
    # lengths[]: symbols given a 2-bit code, every other symbol 0.
    lengths = [0] * 130
    for symbol in symbols_with_two_bits:
        lengths[symbol] = 2
    numbytes = (130 * 2 + 7) // 8
    head = (129 << 24) | (numbytes << 13) | (2 << 8) | (2 << 3)
    bits = []
    for length in lengths:
        bits.extend([(length >> 1) & 1, length & 1])
    body = bytearray()
    acc = idx = 0
    for b in bits:
        acc = (acc << 1) | b
        idx += 1
        if idx == 8:
            body.append(acc)
            acc = idx = 0
    if idx:
        body.append(acc << (8 - idx))
    return struct.pack(">I", head) + bytes(body), body


def _pack_symbols(bits_list):
    out = bytearray()
    acc = idx = 0
    for b in bits_list:
        acc = (acc << 1) | b
        idx += 1
        if idx == 8:
            out.append(acc)
            acc = idx = 0
    if idx:
        out.append(acc << (8 - idx))
    return bytes(out)


def test_ddn_match_copies_out_of_the_window():
    # target "ABCDABCD": four literals, then one match, length 4,
    # offset 4 (symbol 2 length code, offset slot 3).
    value_bits = _pack_symbols([0] * 9 + [1])
    # symbols: four literals (code 00), then match symbol 2 (code 01)
    offsec = _ddn_offset_section()
    lit_start = 22 + len(offsec)
    lit_bytes = b"ABCD"
    lengths = [0] * 130
    lengths[0] = 2
    lengths[2] = 2
    len_section, len_body = _ddn_length_code_section([0, 2])
    lengthstart = lit_start + len(lit_bytes)
    header = bytearray()
    header += (8).to_bytes(4, "big")
    header += (4).to_bytes(2, "big")      # numliterals
    header += (1).to_bytes(2, "big")      # numoffsets
    header += (len(len_section) + len(value_bits)).to_bytes(2, "big")
    header += (4).to_bytes(2, "big")      # literalcompsize
    header += len(offsec).to_bytes(2, "big")
    header += b"\x00" + b"\0" * 6
    check = 0
    for b in header:
        check ^= b
    header.append(check)
    fork = (bytes(header) + offsec + lit_bytes
            + len_section + value_bits)
    f = {"datasize": 8, "datacomp": len(fork),
         "rsrcsize": 0, "rsrccomp": 0,
         "datamethod": 10, "rsrcmethod": 0, "info1": 0x1F, "info2": 0,
         "modification": 0xC9C00000, "creation": 0xC9C00000,
         "type": b"TEXT", "creator": b"TLst", "finderflags": 0,
         "datacrc": 0, "rsrccrc": 0,
         "datadelta": 0, "rsrcdelta": 0}
    image = b"\xAB\xCD\x00\x54" + macarchives._dd_header80(f) + fork
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == b"ABCDABCD"


def test_ddn_run_of_literals():
    # target "AAA": one literal, then symbol 129 (a run of two).
    value_bits = _pack_symbols([0, 0, 0, 1])   # sym 0 (lit), sym 129 (run)
    # code 00 = symbol 0; code 01 = symbol 129
    offsec = _ddn_offset_section()
    lit_bytes = b"AAA"
    len_section, len_body = _ddn_length_code_section([0, 129])
    lengthcompsize = len(len_section) + len(value_bits)
    header = bytearray()
    header += (3).to_bytes(4, "big")
    header += (3).to_bytes(2, "big")      # numliterals
    header += (0).to_bytes(2, "big")      # numoffsets
    header += lengthcompsize.to_bytes(2, "big")
    header += (3).to_bytes(2, "big")      # literalcompsize
    header += len(offsec).to_bytes(2, "big")
    header += b"\x00" + b"\0" * 6
    check = 0
    for b in header:
        check ^= b
    header.append(check)
    fork = bytes(header) + offsec + lit_bytes + len_section + value_bits
    f = {"datasize": 3, "datacomp": len(fork),
         "rsrcsize": 0, "rsrccomp": 0,
         "datamethod": 10, "rsrcmethod": 0, "info1": 0x1F, "info2": 0,
         "modification": 0xC9C00000, "creation": 0xC9C00000,
         "type": b"TEXT", "creator": b"TLst", "finderflags": 0,
         "datacrc": 0, "rsrccrc": 0,
         "datadelta": 0, "rsrcdelta": 0}
    image = b"\xAB\xCD\x00\x54" + macarchives._dd_header80(f) + fork
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == b"AAA"
