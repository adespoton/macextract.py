# macextract

Python library for reading classic Macintosh archives.

Pure standard library, no dependencies. Read-only.

```python
import macextract

with macextract.open("SomeApp.sit.hqx") as archive:
    for entry in archive:
        print(entry.name, entry.data_size, entry.resource_size)
    archive.extract("out/")
```

Status: early. Formats are added in small tested batches; anything not
listed under *Supported* is not supported yet. See
[`PLAN.md`](PLAN.md) for the order of work.

## Supported

| Format | Extensions | Notes |
| --- | --- | --- |
| MacBinary I/II/III | `.bin` | `.macbin` also accepted |
| BinHex 4 | `.hqx` (also `.hex`, `.hcx`) | BinHex 3/2 refused with a clear error |
| AppleSingle / AppleDouble | `.as`, `.bin` (v1), `.ad`, `._foo` | RFC 1740 |
| uuencode | `.uu`, `.uue` | single files, plus Apple MU multi-fork streams |
| btoa | `.btoa` | btoa 4 and 5.2.1 |
| base64 | `.b64` (also `begin-base64` shape) | RFC 2045, lenient decoder |
| MIME attachments | `.eml` | multipart/*, appledouble pairs, pasted uuencode |

## Not supported (yet)

StuffIt classic/5/X, Compact Pro, DiskDoubler, MacCompress, Now
Compress, StuffIt SpaceSaver, Alysis SuperDisk!, Private File, PackIt,
AppleLink, ARC, LZH/LHA, MAR, Apple
Backup, Tomes, zip/gzip/tar/.Z, RAR, 7-Zip, bzip2, xz, and PC formats.
StuffIt X and every other PC/modern format are out of scope, same as
the C project.

## Layout and licence

  * `src/macextract/` — the library
  * `tests/` — pytest suite, generated fixtures only (no real archives
    are committed)
  * `NOTICE` — what is not ours: LGPL-derived files (marked
    `SPDX-License-Identifier: LGPL-2.1-or-later`), the Aladdin SpaceSaver
    tables (`ss_dict.py`, when added) and zlib
  * everything else 0BSD — see `LICENSE`

## API

`macextract.open(path_or_fileobj, /)` — detect and open an archive.
Raises `UnsupportedError` (format not recognised or not supported),
`CorruptError` (recognised but broken), `PasswordRequiredError` /
`BadPasswordError` (encrypted), or `MacExtractError` (base class).

`Archive` — `entries` (list of `Entry`), `read(entry, which="data"|"rsrc")`,
`extract(destination, fork_mode="appledouble"|"data"|"skip-rsrc")`.
`which` defaults to `"data"`. `fork_mode="appledouble"` writes the data
fork to `<name>` and, only when there is a resource fork or Finder info,
a macOS-style `._<name>` AppleDouble alongside it. `"data"` writes the
data fork only. `"skip-rsrc"` like `"data"`.
