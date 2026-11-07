module github.com/nimbacc/kuku-vpn/third_party/corebind

go 1.26.3

require (
        github.com/Diniboy1123/usque v0.0.0-00010101000000-000000000000
        github.com/sagernet/sing-box v1.11.15
)

// The MASQUE engine is vendored in this repository.
replace github.com/Diniboy1123/usque => ../warpcore

// The two QUIC engines share the qpack module path but need different APIs:
// sagernet/quic-go (sing-box) uses the v0.4 pull API, upstream quic-go v0.60
// (usque) the v0.6 streaming API. The vendored copy provides BOTH.
// See third_party/qpack-merged/README.md.
replace github.com/quic-go/qpack => ../qpack-merged
