"""Public entry types and the archive/extract machinery."""

import os
import posixpath
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .errors import CorruptError

# Seconds between the Mac epoch (1904-01-01) and the Unix epoch.
MAC_EPOCH_OFFSET = 2082844800


def _mac_seconds_to_datetime(seconds):
    try:
        return datetime.fromtimestamp(seconds - MAC_EPOCH_OFFSET, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class Entry:
    """One file inside an archive.

    ``name`` is a path relative to the archive root, using ``/`` as the
    separator. Type and creator are the raw four-byte codes. Dates are
    stored as Mac-epoch seconds (seconds since 1904-01-01 UTC); the
    ``created_date``/``modified_date`` properties decode them.
    """

    name: str
    type: bytes = b"????"
    creator: bytes = b"????"
    finder_flags: int = 0
    locked: bool = False
    protected: bool = False
    created: int = 0
    modified: int = 0
    finder_info: bytes | None = None  # 32-byte Finder info, if carried
    data_size: int = 0
    resource_size: int = 0
    _data: bytes = field(default=b"", repr=False)
    _rsrc: bytes = field(default=b"", repr=False)

    @property
    def created_date(self):
        return _mac_seconds_to_datetime(self.created)

    @property
    def modified_date(self):
        return _mac_seconds_to_datetime(self.modified)


def _sanitize_name(name):
    """Make an archive member name safe to use as a relative path.

    Strips anything that is not a normal path segment; drops ``..``
    segments outright. Raises CorruptError if nothing usable remains.
    """
    name = name.replace("\\", "/").replace(":", "/")
    parts = []
    for segment in name.split("/"):
        segment = segment.strip().rstrip(".")
        if segment in ("", ".", ".."):
            continue
        if "\0" in segment:
            segment = segment.replace("\0", "")
        parts.append(segment)
    if not parts:
        raise CorruptError("archive member has no usable name: %r" % name)
    return posixpath.join(*parts)


class Archive:
    """An opened archive. Use :func:`macextract.open` to get one."""

    format = ""

    def __init__(self):
        self.entries = []

    def read(self, entry, which="data"):
        """Return the bytes of one fork (``"data"`` or ``"rsrc"``)."""
        if which == "data":
            return entry._data
        if which == "rsrc":
            return entry._rsrc
        raise ValueError("which must be 'data' or 'rsrc', not %r" % (which,))

    def extract(self, destination, fork_mode="appledouble"):
        """Write the archive's contents under ``destination``.

        ``fork_mode``:

        - ``"appledouble"``: data fork to ``<name>``; resource fork and
          Finder info, when present, to a macOS-style ``._<name>``
          AppleDouble next to it.
        - ``"data"`` / ``"skip-rsrc"``: data fork only; resource forks
          and Finder info are dropped.

        Returns the list of paths written.
        """
        from ._appledouble import appledouble_bytes

        if fork_mode not in ("appledouble", "data", "skip-rsrc"):
            raise ValueError("fork_mode must be 'appledouble', 'data' or 'skip-rsrc'")
        destination = os.fspath(destination)
        written = []
        for entry in self.entries:
            rel = _sanitize_name(entry.name)
            target = os.path.join(destination, *rel.split("/"))
            os.makedirs(os.path.dirname(target) or destination, exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(entry._data)
            written.append(target)
            if fork_mode == "appledouble":
                ad = appledouble_bytes(entry._rsrc, entry.finder_info)
                if ad is not None:
                    dotfile = os.path.join(os.path.dirname(target),
                                           "._" + os.path.basename(target))
                    with open(dotfile, "wb") as handle:
                        handle.write(ad)
                    written.append(dotfile)
        return written

    # context-manager sugar so `with macextract.open(p) as a:` works
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
