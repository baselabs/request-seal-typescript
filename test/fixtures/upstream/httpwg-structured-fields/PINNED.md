**Status:** pinned · **Kind:** conformance decisions · **Updated:** October 9, 2026 · **Governed by:** RFC 4648, RFC 8941, RFC 9651, and the HTTPWG suite · **Review when:** shared corpus decisions change

The adjacent `PINNED.ts` data table owns the decisions used by the test and conformance runner. All eight HTTPWG `can_fail` parsing cases have fixed outcomes. Serialization of their expected values follows the published canonical bytes.

| File | Case | Outcome | Reason |
| --- | --- | --- | --- |
| date.json | syntactic max date - 999,999,999,999,999 | accept | Within the RFC integer range. |
| date.json | syntactic min date - -999,999,999,999,999 | accept | Within the RFC integer range. |
| display-string.json | two lines display string | accept | Ordered occurrences combine with comma-space. |
| string.json | two lines string | accept | Ordered occurrences combine with comma-space. |
| binary.json | unpadded | accept | Complete missing padding before strict decoding. |
| binary.json | partially padded (`:uuueGVsbG8=:`) | reject, both implementations, canonical padding | Nonzero base64 padding bits. |
| binary.json | extra padding | reject | Surplus padding. |
| binary.json | non-zero pad bits (`:iZ==:`) | reject, both implementations, canonical padding | Nonzero base64 padding bits. |
| Supplemental padding probe | `:QR:` | reject, both implementations, canonical padding | Nonzero base64 padding bits after completing missing padding. |

The shared rule for `:iZ==:`, `:uuueGVsbG8=:`, and `:QR:` is **reject, both implementations, canonical padding**. [RFC 4648 Section 3.5](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5) requires zero padding bits for canonical encoding and permits decoders to reject nonzero bits. Under this shared strict decoding policy, [RFC 8941 Section 4.2.7](https://www.rfc-editor.org/rfc/rfc8941.html#section-4.2.7) fails parsing when decoding fails.

The byte-preserved HTTPWG snapshot contains eight `can_fail` entries; `:QR:` is a supplemental shared-rule probe rather than an additional entry in that snapshot. These are the shared acceptance decisions; this file does not establish an executed check of either implementation.
