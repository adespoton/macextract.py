"""StuffIt segments and DiskDoubler ``SPLT`` — one file cut across parts.

Layout evidence
---------------
Both layouts are documented in the C reference project's
``FORMATS.md`` ("Segmented archives (multi-part sets)") and in the C
readers, and both joiner algorithms are carried here as specified:

* StuffIt segments (``src/fmt_sitseg.c``, ``src/fmt_sitseg_probe.c``):
  every part opens with a 100-byte header. Bytes 0-1 are a per-set
  random value StuffIt draws once (XADMaster requires ``B0 56``;
  StuffIt never writes it), byte 2 is zero, byte 3 is the 1-based part
  number, byte 4 is the original file name's length (1-63, no NUL in
  the name), bytes 5-67 the name, then at offset 68 the 26 fingerprint
  bytes every part of a set shares: type (4), creator (4), Finder flags
  (2), creation date (4), modification date (4), resource fork length
  (4), data fork length (4). Bytes 94-95 are a CRC-16/ARC of bytes
  0-93, required. Bytes 96-97 are a CRC-16/ARC running across the set
  over the RESOURCE fork's bytes, zero in a file without one; bytes
  98-99 the same over the DATA fork's bytes. The parts' payloads in
  order are the original file: resource fork first, then data fork.
  No part count is stored; ``rsrclen + datalen`` is the payload total,
  which is how the set terminates itself. Identity is content — name
  length + name bytes + the 26 fingerprint bytes — never the filename.
  Total length at most 2 GB per fork (the HFS limit the engine
  enforces). A one-part set is just a file with a 100-byte hat.

* DiskDoubler ``SPLT`` (``src/fmt_ddseg.c``, ``src/fmt_ddseg_probe.c``,
  derived from specimens, no published description exists): every part
  opens with a 94-byte header. ``SPLT`` at 0-3 and again at 90-93; the
  Mac's TickCount when the set was cut at 4-7 (equal across a set);
  data fork length (4) at 8, resource fork length (4) at 12, type (4)
  at 16, creator (4) at 20, Finder flags (2) at 24; modification date
  (4) at 32, creation date (4) at 36 (modification first, DiskDoubler's
  order); part count (2, 1-256) at 40; 0-based part index (2) at 42;
  this part's payload length (4) at 44; CRC-16/XMODEM of this part's
  payload (2) at 48. There is NO name: the original file's name is the
  host's, from the part's own filename. Concatenating the parts in
  index order yields the original file: DATA fork first, then resource
  fork. The part's declared payload length, not the file's size, bounds
  the part — trailing bytes after the payload are ignored.

Joining
-------
The parts are matched to a set by content, never by filename (the
filename is consulted only for DiskDoubler's missing name). The anchor
may be any part, opened by path; every regular file in the same
directory is a candidate. The joined result is a single entry carrying
both forks, like a MacBinary-enclosed file; whatever archive the joined
file holds is the next layer's problem and is not unwrapped here.

Missing or unreferenceable parts raise CorruptError. File-object input
without a path cannot scan a directory for siblings, so a multi-part
set opened that way raises UnsupportedError; a complete one-part set
opens fine from memory.

StuffIt's running fork CRCs are verified with the reference joiner's
semantics (``unc_segment.c``, ``seg_read``): one running sum per part
walk, folded straight through the set, reset where the resource fork
ends, and each part held to the sum for the fork its last payload byte
falls in. A part with no payload is never checked. Resource bytes that
share their part with the start of the data fork are folded through the
boundary unchecked, exactly as the reference joiner does; nothing here
invents a check the writer's format does not define.

Known gaps, unverified against writers: the ``endD`` resource fork Now
Utilities fat installers carry (part 1 of a fat self-extracting set) is
not read, so such a set is reported incomplete. StuffIt-classic and
StuffIt 5 parts share ONE header layout — there is nothing to
distinguish — so both join here.
"""

import os
import struct

from .._core import Archive, Entry
from .._crc16 import crc16_arc, crc16_ccitt
from ..errors import CorruptError, UnsupportedError

SITSEG_HEAD = 100
SPLT_HEAD = 94
MAX_PARTS = 256
MAC_MAX = 0x7FFFFFFF

_DDSEG_FORMAT = "DiskDoubler SPLT"
_SITSEG_FORMAT = "StuffIt segment"


def _parse_ddseg(head):
    """Validate an ``SPLT`` header. Returns a fields dict or None."""
    if len(head) < SPLT_HEAD:
        return None
    if head[:4] != b"SPLT" or head[90:94] != b"SPLT":
        return None
    nparts, index = struct.unpack_from(">HH", head, 40)
    if nparts < 1 or nparts > MAX_PARTS:
        return None
    if index >= nparts:
        return None
    data, rsrc = struct.unpack_from(">II", head, 8)
    paylen = struct.unpack_from(">I", head, 44)[0]
    if data > MAC_MAX or rsrc > MAC_MAX:
        return None
    if paylen > data + rsrc:
        return None
    return {
        "scheme": "dd",
        "part": index + 1,
        "nparts": nparts,
        "fp": bytes(head[4:30]),
        "data": data,
        "rsrc": rsrc,
        "total": data + rsrc,
        "paylen": paylen,
        "crc": struct.unpack_from(">H", head, 48)[0],
        "type": bytes(head[16:20]),
        "creator": bytes(head[20:24]),
        "flags": struct.unpack_from(">H", head, 24)[0],
        "modified": struct.unpack_from(">I", head, 32)[0],
        "created": struct.unpack_from(">I", head, 36)[0],
        "name_len": 0,
        "name": b"",
    }


def _parse_sitseg(head):
    """Validate a StuffIt-segment header. Returns a fields dict or None."""
    if len(head) < SITSEG_HEAD:
        return None
    if head[2] != 0x00:
        return None
    part = head[3]
    if part == 0:
        return None
    stored_crc = struct.unpack_from(">H", head, 94)[0]
    if stored_crc != crc16_arc(head[:94]):
        return None
    nl = head[4]
    if nl == 0 or nl > 63:
        return None
    name = bytes(head[5:5 + nl])
    if b"\0" in name:
        return None
    rsrc, data = struct.unpack_from(">II", head, 86)
    if rsrc > MAC_MAX or data > MAC_MAX:
        return None
    if rsrc == 0 and data == 0:
        return None
    if rsrc == 0 and (head[96] != 0x00 or head[97] != 0x00):
        return None
    return {
        "scheme": "sit",
        "part": part,
        "fp": bytes(head[68:94]),
        "name_len": nl,
        "name": name,
        "data": data,
        "rsrc": rsrc,
        "total": rsrc + data,
        "type": bytes(head[68:72]),
        "creator": bytes(head[72:76]),
        "flags": struct.unpack_from(">H", head, 76)[0],
        "created": struct.unpack_from(">I", head, 78)[0],
        "modified": struct.unpack_from(">I", head, 82)[0],
    }


def _parse_head(scheme, head):
    if scheme == "dd":
        return _parse_ddseg(head)
    return _parse_sitseg(head)


def _belongs(target, cand):
    """True if ``cand`` (parsed header) belongs to ``target``'s set."""
    if target["scheme"] != cand["scheme"]:
        return False
    if target["scheme"] == "dd":
        return cand["nparts"] == target["nparts"] and cand["fp"] == target["fp"]
    return (cand["name_len"] == target["name_len"]
            and cand["name"] == target["name"]
            and cand["fp"] == target["fp"])


def probe(data):
    if len(data) >= SPLT_HEAD and _parse_ddseg(data[:SPLT_HEAD]) is not None:
        return 70
    if len(data) >= SITSEG_HEAD and _parse_sitseg(data[:SITSEG_HEAD]) is not None:
        return 70
    return 0


def _strip_numeric_suffix(basename):
    """Strip a trailing ``.<digits>`` from a part's filename (the name
    is all a DiskDoubler part carries). A dot in first position, or a
    suffix that is not all digits, is left alone."""
    dot = basename.rfind(".")
    if dot <= 0:
        return basename
    suffix = basename[dot + 1:]
    if not suffix.isdigit():
        return basename
    return basename[:dot]


def _split_name(target, filename):
    if target["scheme"] == "sit":
        try:
            return target["name"].decode("mac_roman")
        except UnicodeDecodeError:
            return target["name"].decode("mac_roman", errors="replace")
    if isinstance(filename, str) and filename:
        base = os.path.basename(filename)
        stripped = _strip_numeric_suffix(base)
        return stripped if stripped else base
    return "split"


def _find_parts(target, anchor_filename):
    """Scan the anchor's directory for parts of this set.

    Returns a dict mapping part number to (header bytes, path, whole
    file bytes). Raises CorruptError if two files claim the same
    part number.
    """
    scheme = target["scheme"]
    dirname = os.path.dirname(anchor_filename) or "."
    head_len = SPLT_HEAD if scheme == "dd" else SITSEG_HEAD
    fmt = _DDSEG_FORMAT if scheme == "dd" else _SITSEG_FORMAT
    parts = {}
    try:
        names = os.listdir(dirname)
    except OSError as error:
        raise CorruptError(
            "%s: cannot list %r to find the other parts of this set: %s"
            % (fmt, dirname, error)) from error
    for name in names:
        path = os.path.join(dirname, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as handle:
                head = handle.read(head_len)
        except OSError:
            continue
        if len(head) < head_len:
            continue
        cand = _parse_head(scheme, head)
        if cand is None or not _belongs(target, cand):
            continue
        try:
            with open(path, "rb") as handle:
                blob = handle.read()
        except OSError:
            continue
        part = cand["part"]
        if part in parts:
            raise CorruptError(
                "%s: two files claim part %d of this set (%r and %r); "
                "refusing to guess" % (fmt, part, parts[part][1], path))
        parts[part] = (head, path, blob)
    return parts


def _ddseg_join(target, parts):
    nparts = target["nparts"]
    missing = [i for i in range(1, nparts + 1) if i not in parts]
    if missing:
        raise CorruptError(
            "DiskDoubler SPLT: missing part(s) %s of %d; this file is one "
            "part of a split set and every part must be in the same "
            "directory" % (", ".join(str(i) for i in missing), nparts))
    joined = bytearray()
    for i in range(1, nparts + 1):
        head, _path, blob = parts[i]
        paylen = struct.unpack_from(">I", head, 44)[0]
        if len(blob) < SPLT_HEAD + paylen:
            raise CorruptError(
                "DiskDoubler SPLT: part %d is %d bytes short of the payload "
                "its header declares" % (i, SPLT_HEAD + paylen - len(blob)))
        payload = blob[SPLT_HEAD:SPLT_HEAD + paylen]
        stored = struct.unpack_from(">H", head, 48)[0]
        if crc16_ccitt(payload) != stored:
            raise CorruptError(
                "DiskDoubler SPLT: part %d fails its payload CRC-16/XMODEM "
                "(0x%04x stored, 0x%04x computed)" % (i, stored,
                                                      crc16_ccitt(payload)))
        joined += payload
        if len(joined) >= target["total"]:
            break
    total = target["total"]
    if len(joined) < total:
        raise CorruptError(
            "DiskDoubler SPLT: the parts carry %d payload byte(s), fewer "
            "than the %d the headers declare" % (len(joined), total))
    return bytes(joined[:total])


def _sitseg_join(target, parts):
    total = target["total"]
    rsrc = target["rsrc"]
    joined = bytearray()
    crc = 0
    crc_pos = 0
    pos = 0
    part_no = 1
    while pos < total:
        if part_no not in parts:
            raise CorruptError(
                "StuffIt segment: missing part %d of this set (%d of %d "
                "payload byte(s) seen); every part must be in the same "
                "directory" % (part_no, pos, total))
        head, _path, blob = parts[part_no]
        chunk = blob[SITSEG_HEAD:]
        if len(chunk) > total - pos:
            # The last part's payload may outgrow the total; the extra
            # bytes are set-member garbage, not payload.
            chunk = chunk[:total - pos]
        end = pos + len(chunk)
        i = 0
        while i < len(chunk):
            if crc_pos == rsrc:
                # The resource fork ended exactly here; the data fork's
                # sum starts from zero.
                crc = 0
            if crc_pos < rsrc:
                n = min(len(chunk) - i, rsrc - crc_pos)
            else:
                n = len(chunk) - i
            crc = crc16_arc(chunk[i:i + n], crc)
            crc_pos += n
            i += n
        if chunk:
            at = 98 if end > rsrc else 96
            stored = struct.unpack_from(">H", head, at)[0]
            if stored != crc:
                which = "data" if end > rsrc else "resource"
                raise CorruptError(
                    "StuffIt segment: part %d fails its running %s-fork "
                    "CRC-16/ARC (0x%04x stored, 0x%04x computed)" % (
                        part_no, which, stored, crc))
        pos = end
        joined += chunk
        part_no += 1
    return bytes(joined)


def _build_archive(target, filename, joined):
    total = target["total"]
    if target["scheme"] == "dd":
        data_fork = joined[:target["data"]]
        rsrc_fork = joined[target["data"]:total]
        fmt = _DDSEG_FORMAT
    else:
        rsrc_fork = joined[:target["rsrc"]]
        data_fork = joined[target["rsrc"]:total]
        fmt = _SITSEG_FORMAT
    flags = target["flags"]
    name = _split_name(target, filename)
    entry = Entry(
        name=name,
        type=target["type"],
        creator=target["creator"],
        finder_flags=flags,
        locked=bool(flags & 0x8000),
        created=target["created"],
        modified=target["modified"],
        finder_info=target["type"] + target["creator"]
        + struct.pack(">H", flags) + b"\0" * 22,
        data_size=len(data_fork),
        resource_size=len(rsrc_fork),
        _data=data_fork,
        _rsrc=rsrc_fork,
    )
    archive = Archive()
    archive.format = fmt
    archive.entries = [entry]
    return archive


def _single_file_complete(target, data):
    if target["scheme"] == "dd":
        return (target["nparts"] == 1
                and len(data) >= SPLT_HEAD
                and target["paylen"] >= target["total"])
    return (target["part"] == 1
            and len(data) >= SITSEG_HEAD
            and len(data) - SITSEG_HEAD >= target["total"])


def open_data(data, password=None, filename=None):
    if len(data) >= SPLT_HEAD and data[:4] == b"SPLT":
        target = _parse_ddseg(data[:SPLT_HEAD])
    else:
        target = None
    if target is None:
        if len(data) >= SITSEG_HEAD:
            target = _parse_sitseg(data[:SITSEG_HEAD])
    if target is None:
        # The probe only speaks when a header parses, so this is a bug
        # in the dispatch, not user input; say so honestly.
        raise CorruptError("split-set part: header failed re-validation")

    if _single_file_complete(target, data):
        # A one-part set is just a file with a header; it reads with no
        # volume source, from memory or disk alike.
        if target["scheme"] == "dd":
            joined = _ddseg_join(target,
                                 {1: (data[:SPLT_HEAD], filename, data)})
        else:
            joined = _sitseg_join(target,
                                  {1: (data[:SITSEG_HEAD], filename, data)})
        return _build_archive(target, filename, joined)

    if not isinstance(filename, str) or not filename:
        fmt = (_DDSEG_FORMAT if target["scheme"] == "dd" else _SITSEG_FORMAT)
        raise UnsupportedError(
            "%s: this is part %d of a split set; joining split sets "
            "requires every part in one directory, opened by path, and "
            "this archive was opened from file-like data without one"
            % (fmt, target["part"]))

    parts = _find_parts(target, filename)
    # The anchor is guaranteed to be there; drop nothing.
    if target["scheme"] == "dd":
        joined = _ddseg_join(target, parts)
    else:
        joined = _sitseg_join(target, parts)
    return _build_archive(target, filename, joined)
