"""Apple Backup reader — the Performa's backup to floppy disks.

An Apple Backup is a set of disks, each holding one file, "Apple
Backup Data" (type 'OBDa', creator 'OBBa', no resource fork),
0x161800 bytes long on a 1.44 MB disk.  Nothing is compressed.  The
layout, as far as this reader uses it:

- Each disk opens with a 0x200-byte header: a version word (0x0103),
  'CMWL' at +2, this disk's 1-based number at +6 and the set's count
  at +8, the backup's start date (a Macintosh date) at +0x0A and
  again at +0x0E, a Str31 drive name at +0x12, the file's length at
  +0x32 and how much of it is used at +0x36 — what follows that is
  not the backup's.
- 0x400 bytes of boot blocks follow, then items starting at 0x600,
  every item on a 0x200 boundary.
- An item header is 0x70 bytes: 'RLDW' at +2, the disk its first part
  is on at +6, the backup's date at +8, this header's own offset in
  the file at +0x0C, the item's name (a Str31) at +0x10, the part
  number (1-based) at +0x30, flags at +0x32 (bit 7 a folder, bit 0
  the System Folder to bless), a validity byte at +0x33 (bit 0: the
  Finder info below it is valid), 16 bytes of FInfo or DInfo at +0x34
  and 16 of FXInfo/DXInfo at +0x44, ioFlAttrib at +0x54 (bit 0
  locked), created and modified Macintosh dates at +0x56 and +0x5A,
  the data and resource forks' whole lengths at +0x5E and +0x62, this
  disk's byte counts for the two forks at +0x66 and +0x6A, and the
  length of the path at +0x6E.  The path follows, from the drive's
  root, ':' between names, then this disk's fork bytes, then zeros to
  the next 0x200.
- An item too big for a disk is cut at the disk's end and continued
  at 0x600 of the next disk under a repeat of its header with the
  part number one higher and this disk's byte counts.  The data fork
  is always finished before any of the resource fork is written.

Sources: Doug Brown, "Legacy Apple Backup file format on floppy
disks" (2013), for every offset above; cross-checked against the C
MacExtract project's reader for the layout and the walking rules, and
against real backup disks for the header offset, the date and the
padding.  Nothing here is transcribed from any of them.

A set is read as a whole: every disk says which disk it is and how
many there are, so a disk opened by path is joined with the disks of
its set sitting in the same directory (identified by the backup's
start date and the set's count — every file in a set is called "Apple
Backup Data", so a name says nothing).  Opened from memory, a
one-disk set reads; a multi-disk set raises UnsupportedError, and a
disk missing from the directory raises CorruptError naming what is
missing.  A damaged item raises CorruptError; nothing is restored
partially.

Folders are path components, not entries (this library's convention,
as in the MAR reader), so an empty folder leaves no trace.  A
folder's DInfo and DXInfo are not carried.  The System Folder's
blessing (bit 0 of +0x32) is not restored, and the backup's start
date is not written into the files' dates — the format does not store
it per item.
"""

import os
import struct

from .._core import Archive, Entry
from ..errors import CorruptError, UnsupportedError

DISK_HDR = 0x200
ABK_FIRST = 0x600
ITEM_HDR = 0x70
ALIGN = 0x200
DISK_MAGIC = b"CMWL"
ITEM_MAGIC = b"RLDW"
_MAC_ROMAN = "mac_roman"


def _u16(buf, off):
    return struct.unpack_from(">H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from(">I", buf, off)[0]


def _disk_ok(buf):
    """The disk header's own claims about itself, or None."""
    if len(buf) < DISK_HDR:
        return None
    number = _u16(buf, 6)
    total = _u16(buf, 8)
    used = _u32(buf, 0x36)
    if buf[2:6] != DISK_MAGIC:
        return None
    if number < 1 or number > total:
        return None
    if used < ABK_FIRST or used > _u32(buf, 0x32):
        return None
    return {"number": number, "total": total, "stamp": bytes(buf[0x0A:0x0E]),
            "used": used}


def _mac_roman(raw):
    try:
        return raw.decode(_MAC_ROMAN)
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _find_set(anchor_disk, anchor_filename):
    """Scan the anchor's directory for the disks of this set.

    Returns a dict mapping disk number to the disk's bytes.  Raises
    CorruptError if two members claim the same disk number.
    """
    anchor = _disk_ok(anchor_disk)
    dirname = os.path.dirname(anchor_filename) or "."
    stamp = anchor["stamp"]
    total = anchor["total"]
    disks = {anchor["number"]: anchor_disk}
    origin = {anchor["number"]: anchor_filename}
    try:
        names = os.listdir(dirname)
    except OSError as error:
        raise CorruptError(
            "Apple Backup: cannot list %r to find the other disks of "
            "this set: %s" % (dirname, error)) from error
    for name in names:
        path = os.path.join(dirname, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as handle:
                head = handle.read(DISK_HDR)
        except OSError:
            continue
        info = _disk_ok(head)
        if info is None:
            continue
        if info["stamp"] != stamp or info["total"] != total:
            continue                    # another backup, or another count
        try:
            with open(path, "rb") as handle:
                blob = handle.read()
        except OSError:
            continue
        number = info["number"]
        if number in disks:
            if disks[number] is not anchor_disk:
                raise CorruptError(
                    "Apple Backup: two files claim disk %d of this set "
                    "(%r and %r); refusing to guess" % (
                        number, origin[number], name))
            continue
        disks[number] = blob
        origin[number] = name
    return disks


def _gather_disks(data, filename):
    info = _disk_ok(data)
    if info is None:
        raise CorruptError("Apple Backup: not a disk of an Apple "
                           "Backup set (bad disk header)")
    total = info["total"]
    if total == 1:
        return {1: data}, info["stamp"]
    if not isinstance(filename, str) or not filename:
        raise UnsupportedError(
            "Apple Backup: this is disk %d of %d; reading a multi-disk "
            "set requires every disk in one directory, opened by path, "
            "and this archive was opened from file-like data without "
            "one" % (info["number"], total))
    disks = _find_set(data, filename)
    missing = [n for n in range(1, total + 1) if n not in disks]
    if missing:
        raise CorruptError(
            "Apple Backup: missing disk(s) %s of %d; every disk of the "
            "set must be in the same directory" % (
                ", ".join(str(n) for n in missing), total))
    return disks, info["stamp"]


def _check_member_disk(disk, number, total, stamp):
    info = _disk_ok(disk)
    if info is None:
        raise CorruptError(
            "Apple Backup: disk %d is not a disk of an Apple Backup "
            "set (bad disk header)" % number)
    if info["number"] != number:
        raise CorruptError(
            "Apple Backup: disk %d carries disk number %d" % (
                number, info["number"]))
    if info["total"] != total:
        raise CorruptError(
            "Apple Backup: disk %d says the set has %d disk(s), disk 1 "
            "said %d" % (number, info["total"], total))
    if info["stamp"] != stamp:
        raise CorruptError(
            "Apple Backup: disk %d belongs to another backup (its "
            "start date differs)" % number)
    used = info["used"]
    if used > len(disk):
        # A disk file cut short ends where it ends.
        used = len(disk)
    return used


def _align(off):
    return (off + ALIGN - 1) & ~(ALIGN - 1)


def _fork_bytes(disk, off, count, what, label):
    end = off + count
    if end > len(disk):                 # caller has already bounded by used
        raise CorruptError(
            "Apple Backup: the %s fork of %r runs past the end of the "
            "disk" % (what, label))
    return disk[off:end]


def _build_entry(info, data_fork, rsrc_fork):
    entry = Entry(name=info["name"])
    entry.data_size = info["dlen"]
    entry.resource_size = info["rlen"]
    entry._data = data_fork
    entry._rsrc = rsrc_fork
    if info["valid"]:
        entry.type = info["type"]
        entry.creator = info["creator"]
        entry.finder_flags = info["finder_flags"]
        entry.locked = info["locked"]
        entry.created = info["created"]
        entry.modified = info["modified"]
        entry.finder_info = info["finder_info"]
    return entry


def open_data(data, password=None, filename=None):
    disks, stamp = _gather_disks(data, filename)
    total = _u16(data, 8)
    entries = []
    # The item whose parts are still arriving, or None.
    pending = None

    for number in range(1, total + 1):
        disk = disks[number]
        used = _check_member_disk(disk, number, total, stamp)
        off = ABK_FIRST

        while off + ITEM_HDR <= used:
            hdr_off = off
            header = disk[hdr_off:hdr_off + ITEM_HDR]
            if disk[hdr_off + 2:hdr_off + 6] != ITEM_MAGIC:
                raise CorruptError(
                    "Apple Backup: disk %d has no item header at byte "
                    "0x%X" % (number, hdr_off))
            if _u32(header, 0x0C) != hdr_off:
                raise CorruptError(
                    "Apple Backup: item at byte 0x%X of disk %d carries "
                    "a header offset of 0x%X" % (
                        hdr_off, number, _u32(header, 0x0C)))
            if bytes(header[8:12]) != stamp:
                raise CorruptError(
                    "Apple Backup: item at byte 0x%X of disk %d belongs "
                    "to another backup (its start date differs)" % (
                        hdr_off, number))
            plen = _u16(header, 0x6E)
            end = hdr_off + ITEM_HDR + plen
            if end > used:
                raise CorruptError(
                    "Apple Backup: item at byte 0x%X of disk %d runs "
                    "past the disk's used length" % (hdr_off, number))
            dh = _u32(header, 0x66)
            rh = _u32(header, 0x6A)
            if dh > used - end or rh > used - end - dh:
                raise CorruptError(
                    "Apple Backup: item at byte 0x%X of disk %d declares "
                    "%d data and %d resource fork byte(s), more than "
                    "the disk holds" % (hdr_off, number, dh, rh))
            dlen = _u32(header, 0x5E)
            rlen = _u32(header, 0x62)
            part = _u16(header, 0x30)
            start = _u16(header, 6)
            is_folder = bool(header[0x32] & 0x80)
            valid = bool(header[0x33] & 1)
            path_raw = bytes(disk[hdr_off + ITEM_HDR:end])
            path = _mac_roman(path_raw)
            label = path.replace(":", "/") or "?"
            fork_at = end
            data_here = _fork_bytes(disk, fork_at, dh, "data", label)
            rsrc_here = _fork_bytes(disk, fork_at + dh, rh,
                                    "resource", label)

            if pending is not None and (
                    (pending["part"] and part != pending["part"])
                    or start != pending["start"]
                    or dlen != pending["dlen"]
                    or rlen != pending["rlen"]):
                raise CorruptError(
                    "Apple Backup: item %r changed its identity between "
                    "parts; the open item is lost" % pending["name"])

            if pending is None:
                if part != 1:
                    raise CorruptError(
                        "Apple Backup: the first part of %r seen is part "
                        "%d; its earlier parts are missing" % (label, part))
                info = {
                    "name": "/".join(
                        _mac_roman(c)
                        for c in path_raw.split(b":")),
                    "dlen": dlen,
                    "rlen": rlen,
                    "valid": valid,
                    "type": bytes(header[0x34:0x38]),
                    "creator": bytes(header[0x38:0x3C]),
                    "finder_flags": _u16(header, 0x3C),
                    "locked": bool(header[0x54] & 0x01),
                    "created": _u32(header, 0x56),
                    "modified": _u32(header, 0x5A),
                    "finder_info": bytes(header[0x34:0x54]),
                }
                if is_folder:
                    # A folder is a path component, not an entry: its
                    # Finder info is not carried, and it has no forks.
                    pending = None
                else:
                    pending = {
                        "part": 1,
                        "start": start,
                        "dlen": dlen,
                        "rlen": rlen,
                        "dleft": dlen,
                        "rleft": rlen,
                        "data": bytearray(),
                        "rsrc": bytearray(),
                        "info": info,
                        "name": info["name"],
                    }

            if pending is not None:
                if rh and dh != pending["dleft"]:
                    raise CorruptError(
                        "Apple Backup: the resource fork of %r begins "
                        "before its data fork is whole" % pending["name"])
                if dh > pending["dleft"] or rh > pending["rleft"]:
                    raise CorruptError(
                        "Apple Backup: item %r declares more fork bytes "
                        "than remain" % pending["name"])
                pending["dleft"] -= dh
                pending["rleft"] -= rh
                pending["data"] += data_here
                pending["rsrc"] += rsrc_here
                if pending["dleft"] == 0 and pending["rleft"] == 0:
                    info = pending["info"]
                    entries.append(_build_entry(
                        info, bytes(pending["data"]),
                        bytes(pending["rsrc"])))
                    pending = None
                else:
                    pending["part"] = part + 1

            off = _align(end + dh + rh)

    if pending is not None:
        raise CorruptError(
            "Apple Backup: item %r spans past the last disk" % pending["name"])

    archive = Archive()
    archive.format = "Apple Backup"
    archive.entries = entries
    return archive


def probe(data):
    info = _disk_ok(data)
    if info is None:
        return 0
    if info["used"] < ABK_FIRST + ITEM_HDR:
        return 0
    if data[ABK_FIRST + 2:ABK_FIRST + 6] != ITEM_MAGIC:
        return 0
    return 80
