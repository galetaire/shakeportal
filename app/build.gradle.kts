import java.util.Properties

plugins {
    // Kotlin is built into the Android plugin since version 9
    id("com.android.application")
}

// Release signing: keystore.properties in the project folder (git-ignored)
// names the keystore and its password. Without it, release builds come out
// unsigned; debug builds use Android's debug key as always.
val signingProps = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

android {
    namespace = "io.github.galetaire.shakeportal"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.galetaire.shakeportal"
        // Android 10: VpnService.Builder.setHttpProxy, the whole point of this app
        minSdk = 29
        targetSdk = 35
        versionCode = 7
        versionName = "0.3.2"
    }

    // shakeportald (the Go DANE proxy, built by scripts/build-go.ps1) is shipped
    // as libshakeportald.so: it must be extracted on install so the app can
    // run it from its native library directory
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    signingConfigs {
        if (signingProps.isNotEmpty()) {
            create("release") {
                storeFile = file(signingProps.getProperty("storeFile"))
                storePassword = signingProps.getProperty("storePassword")
                keyAlias = signingProps.getProperty("keyAlias")
                keyPassword = signingProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
            // Phones only: Zapstore takes one arm64-v8a APK per release.
            // Debug builds keep x86_64 too, for the emulator.
            ndk {
                abiFilters += "arm64-v8a"
            }
        }
    }

    // Java 17 bytecode (Kotlin follows it), built with whatever JDK runs
    // Gradle: Android Studio's own, currently Java 25
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// No libraries: only the Android framework and the Kotlin standard library
dependencies {
}
