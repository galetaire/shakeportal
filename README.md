# ShakePortal

Handshake sites on your Android phone, away from home, checked with DANE:
the app **ShakePortal** (formerly Fingertip), the phone counterpart of [Dit](https://github.com/galetaire/dit), in the
spirit of Fingertip on the desktop.

## Why

At home, Dit (on an Umbrel) resolves Handshake names for the whole network and
its DANE proxy checks secure sites, through a proxy set per Wi-Fi network. On
mobile data neither is reachable. Android has no proxy setting for mobile
data, but a **VPN app can set a system proxy** that applies everywhere
(`VpnService.Builder.setHttpProxy`, Android 10+). This app uses that.

## How it works

- **The VPN** tunnels nothing: it only sets the system proxy to
  `127.0.0.1:8080`, a small proxy inside the app.
- **That proxy** sends ICANN names (example.com, google.com) straight out,
  resolved by Android as usual. Handshake names (`belikebill/`,
  `nathan.woodburn/`) go to the **DANE proxy** on `127.0.0.1:8081`.
- **The DANE proxy** (`go/`, built on
  [letsdane](https://github.com/buffrr/letsdane)) proves the site's TLSA
  record itself, in one of two ways:
  - **Stateless DANE** (HIP-17): if the site's certificate carries its own
    proofs (as [Castell](https://github.com/galetaire/castell) sites do),
    they are verified offline, and no nameserver is asked.
  - Otherwise: the top-level name's on-chain record (its DS records and
    nameservers) comes as an Urkel proof from a Handshake peer (or, as a
    fallback, from the public Stateless DANE proof services) and is
    checked on the phone; the site's nameservers are asked directly; every
    answer is checked with DNSSEC from the on-chain DS.

  No Handshake resolver is trusted, and no hnsd runs on the phone. When the
  TLSA record is proven, the proxy checks the site's certificate against it
  and re-signs the connection with a local CA.
- **The tree roots** that the proofs rest on are checked against Handshake
  block headers that the app syncs from peers every 30 minutes and verifies
  itself (proof of work, difficulty, time), like a light wallet. It starts
  from ~16 days of headers built into the app, so the first sync is a few
  KB. A proof service can therefore not lie, only fail to answer.
- **The local CA** is created on the phone at first start. Its name
  constraints exclude every ICANN top-level domain, so it can never sign a
  certificate for gmail.com or a bank, even if its key leaked.

While the headers are not synced yet (the first seconds after Start, or no
peer reachable), a root is accepted when the proof services agree on it, and
the log says it was not checked.

## Use

1. Copy `app-debug.apk` to the phone and install it.
2. Open ShakePortal → **Start** → accept Android's VPN request.
3. Once: tap **Save CA certificate**, then install it in Settings → Security
   & privacy → More security settings → Encryption & credentials → Install a
   certificate → CA certificate → `ShakePortal-CA.crt` (in Downloads).
4. Browse Handshake sites in Chrome, on Wi-Fi or mobile data. The app lists
   each site and how it was checked (✓ verified from its own certificate or
   with DNSSEC from the chain, – not a DANE site, ✗ refused or failed), and
   shows the CA's SHA-256 fingerprint to compare with Settings → Trusted
   credentials → User.

Chrome trusts user-installed CAs; most other apps do not. Firefox needs "Use
third party CA certificates" (Secret Settings) and DNS over HTTPS off.

## Build

- The DANE proxy (Go, in Docker, as Go is not needed on the PC):
  `.\scripts\build-go.ps1` (add `-Live` to also test against real Handshake
  names and peers, `-Checkpoint` to refresh the built-in headers,
  `go/checkpoint.bin`, from hsd's own checkpoint). It writes `app/src/main/jniLibs/*/libshakeportald.so` and
  `app/src/main/assets/icann-tlds.txt` (IANA's list, fresh).
- The app: Gradle 9.9.1 (wrapper included), Android Gradle plugin 9.5.1 with
  its built-in Kotlin, compileSdk 35, on Android Studio's own Java:
  `$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"; .\gradlew.bat assembleDebug`

The APK is `app/build/outputs/apk/debug/app-debug.apk`.

The icon: the artwork is `art/icon.png`; after changing it, run
`.\scripts\make-icon.ps1` to rebuild the launcher icon from it, then build.

## Notes

- No Android libraries: only the framework and Kotlin. minSdk 29 (Android 10).
- Both proxies listen only on the phone's loopback.
- The VPN routes only an unused private range (10.111.0.0/24); this app is
  excluded from it, so the proxies' own connections go straight out.
- The DANE proxy runs as a child process (a static Linux binary, shipped as a
  native library so Android lets the app run it), not through gomobile: no
  Android NDK needed.
