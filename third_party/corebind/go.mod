module github.com/nimbacc/kuku-vpn/third_party/corebind

go 1.26.3

require (
	github.com/Diniboy1123/usque v0.0.0-00010101000000-000000000000
	github.com/sagernet/sing-box v1.11.15
)

// The MASQUE engine is vendored in this repository.
replace github.com/Diniboy1123/usque => ../warpcore
