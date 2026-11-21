# fingertip-android

Exploring a Handshake + DANE client for Android: the phone counterpart of
[Dit](https://github.com/galetaire/dit) for when you are away from home,
in the spirit of Fingertip on the desktop.

## Why

At home, Dit (on an Umbrel) resolves Handshake names for the whole network and
its DANE proxy checks secure sites, through a proxy set per Wi-Fi network. On
mobile data neither is reachable. Android has no proxy setting for mobile
data, but a **VPN app can set a system proxy** that applies everywhere
(`VpnService.Builder.setHttpProxy`, Android 10+). This app uses that.

## Plan

1. **Step 1 (this prototype):** a VPN app that tunnels nothing and only sets
   the system proxy to a small pass-through proxy inside the app
   (`127.0.0.1:8080`), which logs every site it is asked for. Question to
   answer: does Chrome on mobile data really go through it?
2. **Step 2:** replace that proxy with the DANE proxy: letsdane (Go, as in
   Dit's `docker/dane`), built for Android with gomobile, with the same
   name-constrained local CA. Resolution through hnsd built for Android, or a
   Handshake DoH resolver for addresses plus hnsd for verification.
3. **Later:** Stateless DANE (HIP-0017, as in randomlogin/sane) for sites that
   carry their proofs, on top of plain DANE.

## Build

Gradle 9.9.1 (wrapper included), Android Gradle plugin 9.5.1 with its
built-in Kotlin, compileSdk 35. Runs on Android Studio's own Java (25); no
separate JDK needed.

- Android Studio: open this folder, let it sync, then Build → Build App
  Bundle(s) / APK(s) → Build APK(s).
- Command line (Windows), with Android Studio installed:
  `set JAVA_HOME=C:\Program Files\Android\Android Studio\jbr` then
  `gradlew.bat assembleDebug`.

The APK is `app/build/outputs/apk/debug/app-debug.apk`.

## Test step 1

1. Copy `app-debug.apk` to the phone and install it (allow "install unknown
   apps" for the app you open it with).
2. Turn **Wi-Fi off**, so the phone is on mobile data.
3. Open Fingertip → **Start** → accept Android's VPN request. A key icon
   appears in the status bar.
4. In Chrome, open a few sites (`https://example.com`, `https://wikipedia.org`).
5. Back in Fingertip: each site should be listed as `HTTPS host:443`.

If sites appear, browsers follow the VPN's proxy on mobile data and step 2 can
build on it. If the list stays empty while pages load, they bypass it.

## Notes

- No libraries: only the Android framework and Kotlin. minSdk 29 (Android 10).
- The proxy only listens on the phone's loopback.
- The VPN routes only an unused private range (10.111.0.0/24); this app is
  excluded from it.
