"""CRC-16/AUG-CCITT (polynomial 0x1021, init 0x0000, MSB first), and
CRC-16/ARC (reflected polynomial 0xA001, init 0x0000).

BinHex 4.0 and MacBinary II use the first; StuffIt classic uses the
second (archive header CRC, entry header CRC, and the CRC-16/ARC of
each uncompressed fork — check value 0xBB3D over "123456789").
Written from the published definitions; no code was copied.
"""


def _make_table():
    table = []
    for byte in range(256):
        crc = byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
        table.append(crc)
    return table


_TABLE = _make_table()


def crc16_ccitt(data, crc=0):
    for byte in data:
        crc = ((crc << 8) ^ _TABLE[((crc >> 8) ^ byte) & 0xFF]) & 0xFFFF
    return crc


def _make_arc_table():
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_ARC_TABLE = _make_arc_table()


def crc16_arc(data, crc=0):
    """CRC-16/ARC: reflected polynomial 0xA001, init 0, no final xor.
    ``crc16_arc(b"123456789") == 0xBB3D``."""
    for byte in data:
        crc = (crc >> 8) ^ _ARC_TABLE[(crc ^ byte) & 0xFF]
    return crc
