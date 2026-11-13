"""Archive format handlers. Each module exposes:

- ``probe(data: bytes) -> int`` — 0 if not recognised, higher is more
  confident. Probes are only hints; parsers re-verify everything.
- ``open_data(data: bytes, password=None) -> Archive`` — parse or raise
  CorruptError / PasswordRequiredError / UnsupportedError.
"""

from . import (
    abk, applesingle, binhex, b64, btoa, cpt, dd, macbinary, mar, mime, now,
    packit, segments, sit, sit5, sqp, uuencode, z, arc, lha, tome,
    gzip, zip, tar,
)

FORMATS = [macbinary, binhex, applesingle, uuencode, btoa, b64, mime, packit,
           sit, sit5, sqp, cpt, dd, now, z, arc, lha, segments, mar, abk,
           tome, gzip, zip, tar]
