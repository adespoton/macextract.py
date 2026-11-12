"""CRC-16/AUG-CCITT (polynomial 0x1021, init 0x0000, MSB first).

BinHex 4.0 and MacBinary II both use this CRC. Written from the
published definitions; no code was copied.
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
