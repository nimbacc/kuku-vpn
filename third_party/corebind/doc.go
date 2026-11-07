// Package corebind pins both engines — sing-box libbox and the vendored
// WARP-over-MASQUE engine (usque/warpcore) — into ONE module so a single
// `gomobile bind` produces ONE aar.
//
// Why one aar is mandatory: every gomobile aar embeds its own copy of the
// go.Seq runtime (go.* java classes). Two aars in one app collide at compile
// time ("Duplicate class go.Seq"), and hand-stripping one copy would leave
// two independent Go runtimes sharing a single JNI Seq protocol — refnums,
// proxies and finalizers from both sides would cross-wire and corrupt each
// other. One bind = one runtime = one libkuku.so = correct.
//
// The package itself is never bound; it only forces `go mod tidy` to keep
// both engines in the module graph. The CI binds the original package paths:
//
//	gomobile bind \
//	  -javapkg=io.nekohasekai -libname=kuku \
//	  github.com/sagernet/sing-box/experimental/libbox \
//	  github.com/Diniboy1123/usque/mobile
//
// so the generated classes live at io.nekohasekai.libbox.* and
// io.nekohasekai.warpcore.* (the latter is the Kotlin-facing API).
package corebind

import (
	_ "github.com/Diniboy1123/usque/mobile"
	_ "github.com/sagernet/sing-box/experimental/libbox"
)
