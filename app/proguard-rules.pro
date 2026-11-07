# Keep libbox (gomobile) types — they are reached from Kotlin by name.
-keep class io.nekohasekai.libbox.** { *; }
-dontwarn io.nekohasekai.libbox.**

# Keep warpcore (gomobile, WARP-over-MASQUE engine) the same way: the Go side
# reaches the generated Java glue over JNI and Kotlin calls Warpcore.* by name.
-keep class app.kukuvpn.warpcore.** { *; }
-dontwarn app.kukuvpn.warpcore.**

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
