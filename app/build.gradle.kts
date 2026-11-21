plugins {
    // Kotlin is built into the Android plugin since version 9
    id("com.android.application")
}

android {
    namespace = "io.github.galetaire.fingertip"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.galetaire.fingertip"
        // Android 10: VpnService.Builder.setHttpProxy, the whole point of this app
        minSdk = 29
        targetSdk = 35
        versionCode = 4
        versionName = "0.2.0"
    }

    // fingertipd (the Go DANE proxy, built by scripts/build-go.ps1) is shipped
    // as libfingertipd.so: it must be extracted on install so the app can
    // run it from its native library directory
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
