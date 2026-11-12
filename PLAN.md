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
   (LZW 14-bit), 3 (serialized Huffman) and 13 (LZ + canonical
   Huffman, all five predefined code selectors plus in-stream tables)
   round-trip both forks. Refused with named errors: methods 5/6/7/8/
   14/15 (not implemented), every cipher (PassLock included — none can
   be used yet, so no password is asked for), and Optimizer modules
   other than id 255 (nothing to undo).

10. [x] StuffIt 5 (`.sit`) — the 80-byte banner probe, the entry walk
    with parent-offset folder paths (folders and the marker entry
    after each one are not files), the second block's Finder-info
    gate, comments, entry versions 1 and 3, UTF-8 names.  Methods 0,
    1, 2, 3 and 13 through the classic codecs; methods 14 and 15
    refused by name (Arsenic is next).  Encryption works: the password
    is graded against the archive header's five-byte MD5-of-MD5 hash
    (PasswordRequiredError without one, BadPasswordError for the
    wrong), then each keyed fork is RC4 under MD5(password)[:5] plus
    the fork's own five clear bytes — the scheme the parent project
    measured on archives Aladdin's own software wrote, including the
    hash's position behind archive flag bits 4 and 5.  The entry
    header CRC is carried but not checked, same as the reference
    readers.

Later batches (each with tests): StuffIt arsenic → Compact Pro →
DiskDoubler → Now Compress →
MacCompress (.Z) → ARC → LZH/LHA → PackIt splits → DiskDoubler/StuffIt
split volumes → MAR → Apple Backup → Tomes → zip/gzip/tar → StuffIt
SpaceSaver (with Aladdin tables, attribution per NOTICE). StuffIt X never. PC formats (RAR, 7z,
bzip2, xz) never.
