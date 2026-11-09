plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "app.kukuvpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.kukuvpn"
        minSdk = 24
        targetSdk = 35
        versionCode = 12
        versionName = "1.2.6"
        resourceConfigurations += listOf("en", "fa")
    }

    signingConfigs {
        // Release signing material comes ONLY from keystore.properties which CI
        // (or a local machine) creates from secrets — never from the repo.
        // Parsed manually with pure Kotlin: in Gradle kts scripts the identifier
        // `java` is shadowed by the java-plugin accessor, so java.util.Properties
        // does not compile here.
        if (file("keystore.properties").exists()) {
            val ksProps = file("keystore.properties").readLines()
                .mapNotNull { line ->
                    val i = line.indexOf('=')
                    if (i > 0) line.substring(0, i).trim() to line.substring(i + 1).trim() else null
                }
                .toMap()
            create("release") {
                storeFile = file(ksProps.getValue("storeFile"))
                storePassword = ksProps.getValue("storePassword")
                keyAlias = ksProps.getValue("keyAlias")
                keyPassword = ksProps.getValue("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (signingConfigs.findByName("release") != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            // If no keystore is configured the release APK stays unsigned;
            // CI additionally uploads a debug APK that is signed by the debug key.
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // kuku-core: ONE combined gomobile aar produced by CI (job "core") that
    // binds BOTH engines — sing-box libbox (io.nekohasekai.libbox.*) and the
    // WARP-over-MASQUE engine (io.nekohasekai.warpcore.*). A single aar is
    // mandatory: every gomobile aar embeds its own go.Seq runtime, and two
    // aars collide (duplicate go.Seq) or cross-wire two Go runtimes.
    // Never committed to git.
    implementation(files("libs/warpcore.aar"))

    // Compose (Material 3)
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.appcompat:appcompat:1.7.0") // per-app locale switching
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-service:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // QR scanning (camera + decoder handled by the library activity)
    implementation("com.journeyapps:zxing-android-embedded:4.3.0") { isTransitive = false }
    implementation("com.google.zxing:core:3.5.3")
}
