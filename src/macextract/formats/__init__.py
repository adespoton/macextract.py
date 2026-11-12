"""Archive format handlers. Each module exposes:

- ``probe(data: bytes) -> int`` — 0 if not recognised, higher is more
  confident. Probes are only hints; parsers re-verify everything.
- ``open_data(data: bytes, password=None) -> Archive`` — parse or raise
  CorruptError / PasswordRequiredError / UnsupportedError.
"""

from . import (
    applesingle, binhex, b64, btoa, cpt, dd, macbinary, mime, now, packit,
    sit, sit5, sqp, uuencode,
)

FORMATS = [macbinary, binhex, applesingle, uuencode, btoa, b64, mime, packit,
           sit, sit5, sqp, cpt, dd, now]
