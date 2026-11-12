# Work order

The Python port of (uzTools)/MacExtract. One batch at a time; each
batch ships list + extract for its formats with tests before the next
begins.

1. [ ] Core: errors, Entry/Archive model, detection/sniffing registry,
   safe extraction, AppleDouble `._` writer, generated-fixture test
   harness (writers for every fixture format we commit).
2. [ ] MacBinary I/II/III (`.bin`) — tests: round-trip, bad CRC,
   truncated, MacBinary I vs II vs III, plusnull cases.
3. [ ] BinHex 4 (`.hqx`, `.hex`, `.hcx`) — decoder + encoder (encoder
   needed to generate fixtures); tests: valid, bad CRC, bad name CRC,
   truncated, BinHex 2/3 refusal, RLE edge cases (0x90 runs).
4. [ ] AppleSingle / AppleDouble (`.as`, `.ad`, `._foo`) — RFC 1740;
   entries 1, 2, 9 at least; tests round-trip.
5. [x] uuencode (`.uu`), btoa (`.btoa`), base64/MIME attachments —
   done; MU multi-file layouts merged for uu; multipart/appledouble
   pairs forked entries; pasted uuencode in bodies extracted.
6. [x] PackIt (`.pit`) — stored + Huffman-coded entries; PMa5
   (encrypted) refused with a clear error. CRC polynomial is not
   established by the format notes, so the header and fork CRCs are
   carried but not checked (matches the C reader).
7. [ ] AppleLink Package Translator (`.pkg`) — LZW-compressed container.
8. [ ] Filer wiring (separate task in FILER_IMPLEMENTATION_PLAN.md):
   list archives in a Filer window, extract to a folder, open entries.
   Not done here — this library never imports the Filer.

Later batches (each with tests): StuffIt classic → StuffIt 5 →
StuffIt arsenic → Compact Pro → DiskDoubler → Now Compress →
MacCompress (.Z) → ARC → LZH/LHA → PackIt splits → DiskDoubler/StuffIt
split volumes → MAR → Apple Backup → Tomes → zip/gzip/tar → StuffIt
SpaceSaver (with Aladdin tables, attribution per NOTICE). StuffIt X never. PC formats (RAR, 7z,
bzip2, xz) never.
