"""MIME messages (RFC 2045/2046/1740) — how a Macintosh file crossed
the Internet once mail stopped being seven-bit: a base64 or
quoted-printable part per attachment, and for files that had to arrive
with both forks, multipart/appledouble (RFC 1740), an
application/applefile header part in front of the data fork.

The stdlib :mod:`email` package does the heavy lifting (header parsing,
RFC 2231 parameter decoding, nested multipart walking, transfer
decoding). This module adds what the Filer needs:

  * attachments become entries; the message body (a text/... part with
    no filename) is not an entry — unless it is uuencode that got pasted
    into the message, in which case its entries are taken instead;
  * parts with no filename are named ``part1``, ``part2`` ... (mpack's
    convention);
  * multipart/appledouble pairs an application/applefile part (an
    AppleDouble header: name, Finder info, resource fork) with the
    following part (the data fork) and yields one entry with both forks;
  * uuencoded or base64 attachments keep their own names.
"""

from email import policy
from email.parser import BytesParser

from .._core import Archive, Entry
from ..errors import CorruptError
from . import applesingle, uuencode


def _decode_part_bytes(part):
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is not None:
        return payload
    raw = part.get_payload()
    if isinstance(raw, str):
        return raw.encode("latin-1", errors="replace")
    return b""


def _part_filename(part):
    name = part.get_filename()
    if name:
        return name
    ctype_name = part.get_param("name", header="content-type")
    if ctype_name:
        return ctype_name
    return None


def _parse_applefile(data):
    """Parse an application/applefile part into an Entry skeleton."""
    if len(data) < 4:
        raise CorruptError("MIME: applefile part too small")
    import struct
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic == applesingle.APPLESINGLE_MAGIC:
        archive = applesingle._parse(data, kind="single")
    elif magic == applesingle.APPLEDOUBLE_MAGIC:
        archive = applesingle._parse(data, kind="double")
    else:
        raise CorruptError("MIME: applefile part has bad magic")
    return archive.entries[0]


def _walk_entries(message):
    entries = []
    pending_apple = None  # Entry with rsrc/finder from an applefile part
    part_counter = 0

    for part in message.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        payload = _decode_part_bytes(part)

        if ctype == "application/applefile":
            try:
                pending_apple = _parse_applefile(payload)
                continue
            except CorruptError:
                pass  # not a readable header: fall through as a file

        name = _part_filename(part)
        if name is None and ctype.startswith("text/"):
            # Possibly the message body — or a uuencode pasted into it.
            if payload.strip():
                try:
                    uue = uuencode.open_data(payload)
                except CorruptError:
                    uue = None
                if uue is not None:
                    entries.extend(uue.entries)
                    continue
            if pending_apple is not None:
                entries.append(pending_apple)
                pending_apple = None
            continue
        if name is None:
            if pending_apple is not None:
                name = pending_apple.name
            else:
                part_counter += 1
                name = "part%d" % part_counter

        if pending_apple is not None:
            apple = pending_apple
            if name and name != apple.name:
                apple.name = name
            apple._data = payload
            apple.data_size = len(payload)
            entries.append(apple)
            pending_apple = None
            continue

        entries.append(Entry(name=name, data_size=len(payload), _data=payload))

    if pending_apple is not None:
        entries.append(pending_apple)
    return entries


def _has_mime_markers(message):
    if message.get("MIME-Version") is not None:
        return True
    for part in message.walk():
        if part.is_multipart():
            return True
    if message.get("Content-Type") is not None and \
            message.get("Content-Transfer-Encoding") is not None:
        return True
    return False


def _parse(data, filename_hint=None):
    if not data:
        raise CorruptError("MIME: empty file")
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as error:
        raise CorruptError("MIME: %s" % error)
    if not _has_mime_markers(message):
        raise CorruptError("MIME: no MIME headers found")
    entries = _walk_entries(message)
    if not entries:
        raise CorruptError("MIME: no attachments found")
    archive = Archive()
    archive.format = "MIME"
    archive.entries = entries
    return archive


def probe(data):
    if not data:
        return 0
    try:
        message = BytesParser(policy=policy.default).parsebytes(data[:8192])
    except Exception:
        return 0
    if message.get("MIME-Version") is not None:
        return 75
    ctype = (message.get("Content-Type") or "").lower()
    if ctype.startswith("multipart/"):
        return 75
    if message.get("Content-Type") is not None and \
            message.get("Content-Transfer-Encoding") is not None:
        return 60
    return 0


def open_data(data, password=None, filename=None):
    # MIME messages have no encryption; a supplied password is unused.
    return _parse(data)
