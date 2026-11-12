"""macextract: read classic Macintosh archives from Python.

    import macextract
    with macextract.open("SomeApp.bin") as archive:
        for entry in archive:
            print(entry.name, entry.data_size)
        archive.extract("out/")
"""

import builtins
import os

from . import formats
from ._core import Archive, Entry
from .errors import (
    BadPasswordError,
    CorruptError,
    MacExtractError,
    PasswordRequiredError,
    UnsupportedError,
)

__version__ = "0.1.0"

__all__ = [
    "open",
    "Archive",
    "Entry",
    "MacExtractError",
    "UnsupportedError",
    "CorruptError",
    "PasswordRequiredError",
    "BadPasswordError",
    "__version__",
]


def open(file, password=None):  # noqa: A001 - mirrors builtin open, deliberately
    """Open a classic Macintosh archive.

    ``file`` may be a path or a binary file object positioned at the
    start of the archive. Raises UnsupportedError if the format is not
    recognised, CorruptError if it is damaged, or
    PasswordRequiredError/BadPasswordError for encrypted archives.
    """
    if hasattr(file, "read"):
        data = file.read()
        if isinstance(data, str):
            raise TypeError("file object must be opened in binary mode")
        filename = getattr(file, "name", None)
    else:
        filename = os.fspath(file)
        with builtins.open(filename, "rb") as handle:
            data = handle.read()

    def _score(module):
        try:
            return module.probe(data)
        except Exception:
            return 0

    scored = sorted(
        ((_score(module), module) for module in formats.FORMATS),
        key=lambda item: -item[0],
    )
    candidates = [(score, module) for score, module in scored if score > 0]
    if not candidates:
        raise UnsupportedError(
            "unrecognised archive format (starts with %s)" % data[:16].hex(" "))
    first_error = None
    for score, module in candidates:
        try:
            archive = module.open_data(data, password=password, filename=filename)
        except CorruptError as error:
            if first_error is None:
                first_error = error
            continue
        except MacExtractError:
            raise
        except Exception as error:
            # Parsers are trusted to raise CorruptError; a bug must not
            # leak out as one.
            if first_error is None:
                first_error = CorruptError("%s: %s" % (module.NAME if hasattr(module, "NAME") else module.__name__.rsplit(".", 1)[-1], error))
            continue
        _pair_appledouble_sibling(archive, filename)
        return archive
    raise first_error


def _pair_appledouble_sibling(archive, filename):
    """Fill in the data fork of a lone ``._foo`` from the sibling ``foo``."""
    if archive.format != "AppleDouble" or not filename:
        return
    if not isinstance(filename, str):
        return
    entry = archive.entries[0]
    if entry.data_size or entry._data:
        return
    path = os.fspath(filename)
    base = os.path.basename(path)
    if not base.startswith("._"):
        return
    sibling = os.path.join(os.path.dirname(path), base[2:])
    if not os.path.isfile(sibling):
        return
    with builtins.open(sibling, "rb") as handle:
        entry._data = handle.read()
    entry.data_size = len(entry._data)
