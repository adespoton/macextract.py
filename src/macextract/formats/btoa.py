"""btoa 5.2.1 (.btoa) — Paul Rutter's base-85 ASCII armour.

Layout: an ``xbtoa Begin`` line (version 4) or ``xbtoa5 <perline>
<name> Begin`` line (version 5), body lines of base-85 digits offset by
'!', and an ``xbtoa End N <len> <lenhex> E <eor> S <sum> R <rot>`` line.
``z`` encodes four zero bytes and (version 5 only) ``y`` encodes four
spaces. Version 5 lines carry one trailing character, the checksum of
the encoded characters on that line modulo 85. Three whole-stream
checksums are compared against the End line: eor (xor), sum (+ ch+1)
and rot (rotate left 1 with wraparound, then + ch). In version 5 the
checksums cover the encoded characters as read; in version 4 they cover
the decoded bytes as produced. Facts from the published btoa manual and
the C project's notes; no code was copied.
"""

from .._core import Archive, Entry
from ..errors import CorruptError


def _lines(data):
    for raw in data.split(b"\n"):
        yield raw.rstrip(b"\r")


def _hex(text):
    try:
        return int(text, 16)
    except ValueError:
        raise CorruptError("btoa: bad hex value %r" % text)


def _dec(text):
    try:
        value = int(text, 10)
    except ValueError:
        raise CorruptError("btoa: bad decimal value %r" % text)
    if value < 0:
        raise CorruptError("btoa: bad decimal value %r" % text)
    return value


def _chk(state, ch):
    state["eor"] ^= ch
    state["sum"] = (state["sum"] + ch + 1) & 0xFFFFFFFF
    rot = state["rot"]
    state["rot"] = (((rot << 1) | (rot >> 31)) & 0xFFFFFFFF) + ch


def _parse(data, name_hint=None):
    if not data:
        raise CorruptError("btoa: empty file")

    newver = 0
    name = None
    started = False
    end_fields = None
    body = []
    for line in _lines(data):
        if not started:
            if line.startswith(b"xbtoa"):
                fields = line.split()
                if len(fields) >= 2 and fields[0] == b"xbtoa" and fields[1] == b"Begin":
                    newver = 0
                    started = True
                    continue
                if len(fields) >= 4 and fields[0] == b"xbtoa5" and fields[1].isdigit():
                    name_field = fields[2]
                    if name_field != b"-":
                        name = name_field.decode("latin-1")
                    newver = 1
                    started = True
                    continue
            continue
        if line.startswith(b"xbtoa"):
            fields = line.split()
            if len(fields) >= 11 and fields[0] in (b"xbtoa", b"xbtoa5") and fields[1] == b"End":
                end_fields = fields
                break
            raise CorruptError("btoa: malformed End line")
        if line.strip():
            body.append(line)
    if not started:
        raise CorruptError("btoa: missing begin line")
    if end_fields is None:
        raise CorruptError("btoa: missing End line")

    want = _dec(end_fields[3].decode())
    if want != _hex(end_fields[4].decode()):
        raise CorruptError("btoa: End line length mismatch")

    state = {"eor": 0, "sum": 0, "rot": 0}
    out = bytearray()
    code = 0
    count = 0
    group = bytearray(4)
    have = False

    def release(n):
        nonlocal have
        if have:
            out.extend(group[:n])
            have = False

    for line in body:
        datalen = len(line)
        if newver:
            datalen -= 1
            if datalen < 0:
                raise CorruptError("btoa: empty line in version 5 stream")
        for index in range(datalen):
            ch = line[index]
            if newver:
                _chk(state, ch)
            if 33 <= ch < 33 + 85:
                if count == 0:
                    release(4)
                    code = ch - 33
                else:
                    code = code * 85 + (ch - 33)
                count += 1
                if count == 5:
                    group[0] = (code >> 24) & 0xFF
                    group[1] = (code >> 16) & 0xFF
                    group[2] = (code >> 8) & 0xFF
                    group[3] = code & 0xFF
                    if not newver:
                        for byte in group:
                            _chk(state, byte)
                    have = True
                    count = 0
            elif ch == ord("z") or (newver and ch == ord("y")):
                if count != 0:
                    raise CorruptError("btoa: z/y escape inside a 5-character group")
                release(4)
                if ch == ord("z"):
                    out += b"\0" * 4
                else:
                    out += b" " * 4
                if not newver:
                    fill = 0x00 if ch == ord("z") else 0x20
                    for _ in range(4):
                        _chk(state, fill)
            else:
                raise CorruptError("btoa: invalid character 0x%02x" % ch)
        if newver:
            if line[-1] != 33 + (state["sum"] % 85):
                raise CorruptError("btoa: per-line checksum mismatch")

    real = ((want - 1) & 3) + 1 if want else 0
    release(real)
    if len(out) != want:
        raise CorruptError("btoa: decoded length %d != declared %d" % (len(out), want))

    eor = _hex(end_fields[6].decode())
    osum = _hex(end_fields[8].decode())
    orot = _hex(end_fields[10].decode())
    if eor != state["eor"] or osum != state["sum"] or orot != state["rot"]:
        raise CorruptError("btoa: stream checksum mismatch")

    entry = Entry(
        name=name or name_hint or "unnamed",
        data_size=len(out),
        _data=bytes(out),
    )
    archive = Archive()
    archive.format = "btoa v5" if newver else "btoa v4"
    archive.entries = [entry]
    return archive


def probe(data):
    for line in list(_lines(data[:4096]))[:32]:
        if line.startswith(b"xbtoa"):
            fields = line.split()
            if len(fields) >= 2 and (
                (fields[0] == b"xbtoa" and fields[1] == b"Begin")
                or (fields[0] == b"xbtoa5" and fields[1].isdigit())
            ):
                return 85
    return 0


def open_data(data, password=None, filename=None):
    # btoa has no encryption; a supplied password is simply unused.
    hint = filename
    if hint:
        base = hint.replace("\\", "/").rsplit("/", 1)[-1]
        if base.lower().endswith(".btoa"):
            base = base[:-5]
        hint = base or None
    return _parse(data, name_hint=hint)
