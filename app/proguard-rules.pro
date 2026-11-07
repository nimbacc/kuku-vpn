# Keep libbox (gomobile) types — they are reached from Kotlin by name.
-keep class io.nekohasekai.libbox.** { *; }
-dontwarn io.nekohasekai.libbox.**

# Keep the warpcore (gomobile, WARP-over-MASQUE engine) classes the same way:
# the Go side reaches the generated Java glue over JNI and Kotlin calls
# Warpcore.* by name. The engine ships inside the combined aar under
# io.nekohasekai.warpcore (libbox keeps io.nekohasekai.libbox).
-keep class io.nekohasekai.warpcore.** { *; }
-dontwarn io.nekohasekai.warpcore.**

# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** { kotlinx.serialization.KSerializer serializer(...); }
-keep,includedescriptorclasses class app.kukuvpn.**$$serializer { *; }
-keepclassmembers class app.kukuvpn.** { *** Companion; }
-keepclasseswithmembers class app.kukuvpn.** { kotlinx.serialization.KSerializer serializer(...); }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
