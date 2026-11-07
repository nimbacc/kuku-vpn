# qpack-merged (vendored, patched)

This is a vendored copy of **github.com/quic-go/qpack v0.6.0** (MIT license,
© Marten Seemann et al.) with two small compatibility shims, so that the two
QUIC engines of this repository can live in ONE gomobile binary:

- **sing-box v1.11.x** pins `github.com/sagernet/quic-go v0.49.0-beta.1`,
  which still uses the qpack **v0.4 pull API**
  (`NewDecoder(handler)`, `Decoder.DecodeFull(p)`).
- **usque** (the WARP-over-MASQUE engine) needs upstream
  `github.com/quic-go/quic-go v0.60.0`, which uses the qpack **v0.6
  streaming API** (`NewDecoder()`, `Decoder.Decode(p) DecodeFunc`).

Both quic-go forks import the SAME module path `github.com/quic-go/qpack`,
and Go modules resolve to a single version per path. Upstream qpack v0.6.0
removed the v0.4 API, which breaks the sagernet fork's compile. This copy
serves both:

1. `NewDecoder(fieldHandler ...func(HeaderField))` — variadic, so both
   `NewDecoder()` (upstream) and `NewDecoder(handler)` (sagernet) compile.
   The handler is a no-op for this static-table-only decoder.
2. `Decoder.DecodeFull(p)` — pull-style decoding implemented on top of the
   v0.6 `Decode` iterator.

The `replace` in `third_party/corebind/go.mod` points here. Everything else
(encoder, static table, varint, HeaderField) is untouched upstream v0.6.0.
