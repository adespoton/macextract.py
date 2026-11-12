# macextract.py

Python library for reading classic Macintosh archives. A Python
conversion of the [MacExtract](https://github.com/uzTools/MacExtract)
project (uzTools/MacExtract, C); the formats are reimplemented from
published specifications and the tested behavior of the C project, not
transcribed from it.

The import package is `macextract`:

    pip install macextract.py

    pip install git+https://github.com/adespoton/macextract.py

Classetta (the Classic Mac emulation front end) depends on
macextract.py; its Filer browses, extracts and launches archives, and
inherits every registered format automatically.

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
| PackIt | `.pit` | stored and Huffman-coded; PMa5 refused (cipher undocumented) |
| AppleLink package | `.pkg` | SqueezePlay; stored and LZW-compressed forks, v0/v1 |
| StuffIt classic | `.sit` | methods 0/1/2/3/13/15 (stored, RLE-90, LZW-14, Huffman, LZ+Huffman, Arsenic), folders, CRC-16 checks; other methods, encryption and optimizer modules refused by name |
| StuffIt 5 | `.sit` (banner) | folders with parent-offset paths, UTF-8 names, Finder-info gate, comments, entry versions 1 and 3; methods 0/1/2/3/13/15 (Arsenic); encrypted archives via `password=` (MD5 grade, RC4 forks); method 14 refused by name |
| Compact Pro | `.cpt` | folders rebuilt from the directory-count scheme, comments, RLE and LZH (LZSS + canonical Huffman) forks; encrypted archives via `password=` (its CRC-table cipher); segmented sets refused by name |

## Not supported (yet)

StuffIt X, StuffIt classic's methods 5/6/7/8/14, StuffIt 5's
method 14 (code-only, no spec), DiskDoubler, MacCompress, Now
Compress, StuffIt SpaceSaver, Alysis SuperDisk!, Private File, ARC, LZH/LHA, MAR, Apple
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
