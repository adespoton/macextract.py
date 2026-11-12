"""RLE-90 run-length decoding (StuffIt method 1, ARC method 8's
filter, and part of Squeeze).

Bytes pass through unchanged. ``0x90 0x00`` is a literal 0x90; after
an escape, count n >= 2 repeats the previous byte n-1 times in total
(the escape's own first emission is the byte before the repeats, so
the stream carries n = run length + 1); ``0x90 0x01`` is illegal.
A run of 0x90 bytes is therefore written as literal, then escaped
repeats. Written from the format's published description; no code was
copied.
"""

from .errors import CorruptError

ESC = 0x90


def rle90_decode(data, out_len, offset=0, limit=None):
    """Decode exactly ``out_len`` bytes; returns them. Raises
    CorruptError on an illegal count or when the stream runs out.
    """
    if out_len < 0:
        raise CorruptError("RLE-90: output length must not be negative")
    if out_len == 0:
        return b""
    end = len(data) if limit is None else offset + limit
    pos = offset
    out = bytearray()
    last = 0
    esc = False
    run = 0                       # repeats still owed by a run in progress
    while len(out) < out_len:
        if run:
            out.append(last)
            run -= 1
            continue
        if pos >= end:
            raise CorruptError("RLE-90: stream exhausted before the fork's length")
        byte = data[pos]
        pos += 1
        if esc:
            esc = False
            if byte == 0:
                last = ESC
                out.append(ESC)
            elif byte == 1:
                raise CorruptError("RLE-90: 0x90 0x01 is not a legal count")
            else:
                run = byte - 2
                out.append(last)
        elif byte == ESC:
            esc = True
        else:
            last = byte
            out.append(byte)
    return bytes(out)
