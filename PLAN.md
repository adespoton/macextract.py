# Work order

The Python port of (uzTools)/MacExtract. One batch at a time; each
batch ships list + extract for its formats with tests before the next
begins.

1. [x] Core: errors, Entry/Archive model, detection/sniffing registry,
   safe extraction, AppleDouble `._` writer, generated-fixture test
   harness (writers for every fixture format we commit).
2. [x] MacBinary I/II/III (`.bin`) — tests: round-trip, bad CRC,
   truncated, MacBinary I vs II vs III, plusnull cases.
3. [x] BinHex 4 (`.hqx`, `.hex`, `.hcx`) — decoder + encoder (encoder
   needed to generate fixtures); tests: valid, bad CRC, bad name CRC,
   truncated, BinHex 2/3 refusal, RLE edge cases (0x90 runs).
4. [x] AppleSingle / AppleDouble (`.as`, `.ad`, `._foo`) — RFC 1740;
   entries 1, 2, 9 at least; tests round-trip.
5. [x] uuencode (`.uu`), btoa (`.btoa`), base64/MIME attachments —
   done; MU multi-file layouts merged for uu; multipart/appledouble
   pairs forked entries; pasted uuencode in bodies extracted.
6. [x] PackIt (`.pit`) — stored + Huffman-coded entries; PMa5
   (encrypted) refused with a clear error. CRC polynomial is not
   established by the format notes, so the header and fork CRCs are
   carried but not checked (matches the C reader).
7. [x] AppleLink Package Translator (`.pkg`) — SqueezePlay; stored and
   Unix compress LZW (13-bit, block mode) forks; v0 flat and v1 HFS
   directories; folder levels become path components.
8. [x] Filer wiring (separate task in FILER_IMPLEMENTATION_PLAN.md,
   Classetta task 23): the Filer sniffs with this library's format
   registry, so list, browse, launch and extract work for every
   registered format with no per-format Filer changes.

9. [x] StuffIt classic (`.sit`) — archive header, 112-byte entry
   headers, folder markers as path components, CRC-16/ARC on headers
   and decoded forks. Compression methods 0 (stored), 1 (RLE-90), 2
   (LZW 14-bit), 3 (serialized Huffman), 13 (LZ + canonical
   Huffman, all five predefined code selectors plus in-stream tables)
   and 15 (Arsenic, item 11) round-trip both forks. Refused with named
   errors: methods 5/6/7/8/14 (not implemented), every cipher (PassLock
   included — none can be used yet, so no password is asked for), and
   Optimizer modules other than id 255 (nothing to undo).

10. [x] StuffIt 5 (`.sit`) — the 80-byte banner probe, the entry walk
    with parent-offset folder paths (folders and the marker entry
    after each one are not files), the second block's Finder-info
    gate, comments, entry versions 1 and 3, UTF-8 names.  Methods 0,
    1, 2, 3 and 13 through the classic codecs and 15 (Arsenic, item
    11); method 14 refused by name.  Encryption works: the password
    is graded against the archive header's five-byte MD5-of-MD5 hash
    (PasswordRequiredError without one, BadPasswordError for the
    wrong), then each keyed fork is RC4 under MD5(password)[:5] plus
    the fork's own five clear bytes — the scheme the parent project
    measured on archives Aladdin's own software wrote, including the
    hash's position behind archive flag bits 4 and 5.  The entry
    header CRC is carried but not checked, same as the reference
    readers.

11. [x] Arsenic (StuffIt method 15) — the decoder written from
    Matthew Russotto's spec and checked against the parent C project's
    ``sit_arsenic.c`` and XADMaster's ``XADStuffItArsenicHandle``
    line by line: the quotient arithmetic coder (integer division and
    rounding exactly as specified) under the nine adaptive models,
    the selector stream with its zero-run counting, move-to-front, the
    counting-sort inverse BWT from the block header's primary index,
    the randomisation table, the byte-stuffing RLE, and the stream's
    own CRC-32 over the output.  Block size ``1 << (v + 9)`` from four
    stream bits; both containers skip their CRC-16 for method 15 (the
    field is zero) because the stream checks itself.  The fixture
    encoder cuts the RLE whole-file and packs blocks at run-token
    boundaries, never between a run's four equal bytes and their
    count byte — the one split the references' per-block RLE state
    would misread.  26 tests, generated data only.

12. [x] Compact Pro (`.cpt`) — the 8-byte archive header with the
    signature byte, the index CRC (reflected CRC-32, seeded
    0xFFFFFFFF, compared without the final xor) gateing the whole
    walk, folders rebuilt from the directory-count scheme (every
    header decrements its whole stack of budgets), the comment, the
    45-byte file records, and both forks stored resource-first with
    one CRC-32 across the pair.  The ``0x81 0x82`` run filter and the
    LZH layer (LZSS + three canonical Huffman codes, 8 KB window,
    the count byte in front of each code list, no Reverse16, the
    offset taken exactly with 0 legal, the block flush rule) both
    round-trip through the container; the fixture encoder cuts the
    RLE first and LZH after, the decoder's order backwards, since the
    decoder runs LZH before the filter.  Encrypted entries decode
    under ``password=`` with Compact Pro's CRC-table cipher (the
    password becomes a nine-byte key folded into two 32-bit CRC
    registers seeded 0x01234567/0x89ABCDEF); an encrypted stream
    opens with eight decrypted, discarded bytes counted in the first
    non-empty fork, and the cipher runs across both forks without
    resetting.  Nothing verifies the password but the entry's CRC-32,
    so a wrong one raises BadPasswordError only after a full decode.
    Volume numbers other than 1 and segmented sets are refused by
    name.  38 tests, generated data only.

13. [x] DiskDoubler (`.dd`, `.ddar`, `.dda2`) — three containers over
    one fork codec.  Single-file images (0xABCD0054; the 1990 variant
    0xABCD0030, 48 bytes, never garbled, absent checksums read as
    zero), ``DDAR`` (78-byte header, 124-byte records, folders derived
    from path components with a closing record that is a byte copy of
    the folder record with byte 73 set, tested before the record is
    treated as an entry) and ``DDA2`` (62-byte header, variable-length
    records each stating their own size, ``0xBBBB`` end record or a
    markerless ending within 46 bytes of the declared end).  Folders
    rebuilt from the depth fields: DDA2's depth at +38 is the number of
    enclosing folders plus 2 for files and folders alike, and a folder
    record states the depth its contents will use; DDAR's closing
    copy is tested first.  All ten methods round-trip (0 stored,
    1 LZW with the ``1f 9d`` header, 2 and 5 splay-tree with shared or
    per-context trees, 3 RLE-90, 4 Huffman, 6 and 9 AD, 7 STAC,
    8 Compact Pro's LZH/RLE with the 16-byte prefix and CRC-16/ARC,
    10 DDn with two canonical Huffman codes and the offset-slot table,
    MSB-first).  The 0x5a header garble applies to methods 1, 2 and 5
    only, as in the C project; the delta form (distance 1) sits outside
    every coder and is checked before the checksum, which sums the
    pre-delta bytes.  Stored checksums for methods 6, 7, 9 and 10 are
    per-block XORs, and method 7 also pins a one-byte XOR of the
    fork; methods 1–5 carry a 16-bit sum with the header trio folded in
    for method 1.  Finder info carried for single-file images and DDAR
    records.  60 tests, generated data only.

Later batches (each with tests): Now Compress →
MacCompress (.Z) → ARC → LZH/LHA → PackIt splits → DiskDoubler/StuffIt
split volumes → MAR → Apple Backup → Tomes → zip/gzip/tar → StuffIt
SpaceSaver (with Aladdin tables, attribution per NOTICE). StuffIt X never. PC formats (RAR, 7z,
bzip2, xz) never.
