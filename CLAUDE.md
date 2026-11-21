# fingertip-android: project context

Handoff notes from the Dit session (16–19 Nov 2026). This file records the
goal, what is built, what has been learned and what comes next. README.md
explains the app to humans; this file is for picking the work up.

## What this is

An Android app by galetaire (GitHub user; repos galetaire/dit,
galetaire/fingertip-dit, galetaire/castell, galetaire/bob-dns,
galetaire/finestra): a Handshake (HNS) + DANE client for the phone, for use
**away from home**, in the spirit of Fingertip on the desktop
(~/Fingertip-dit is the owner's desktop fork; its Go code is in
~/Fingertip-dit/third_party/fingertip).

At home this is already solved by **Dit** (~/Documents/GitHub/Dit, an
umbrelOS app on a Raspberry Pi 4 at 192.168.1.27): Dit resolves Handshake
names for the whole network (router DNS = Umbrel), and its DANE proxy
(port 9053, auto-config file http://192.168.1.27:9053/proxy.pac) checks
DANE sites and re-signs them with a local CA installed on each device. On the
phone that proxy is set per Wi-Fi network, so it does not work on mobile
data. Tailscale would solve that, but the owner does not use Tailscale.

## Key idea

Android has no proxy setting for mobile data, but a **VPN app can set a
system proxy** (`VpnService.Builder.setHttpProxy`, Android 10+) that applies
on Wi-Fi and mobile data alike, and Chrome honours it. The VPN tunnels
nothing; it only carries the proxy setting. The proxy runs inside the app on
the phone's loopback.

## State: step 1 built and proven on the phone (0.0.2)

- Repo: ~/Documents/GitHub/fingertip-android, branch main, `git init` done,
  files staged, **nothing committed, no remote**. Commit/push only when the
  owner asks.
- Package `io.github.galetaire.fingertip`, app name "Fingertip", version
  0.0.1, minSdk 29, targetSdk/compileSdk 35. No libraries: Android framework
  + Kotlin only, UI built in code (no XML layouts, no AndroidX).
- Files (app/src/main/java/io/github/galetaire/fingertip/):
  - `ProxyVpnService.kt`: VpnService; address 10.111.0.1/32, route only the
    unused 10.111.0.0/24, `addDisallowedApplication(packageName)` (the
    proxy's own connections go straight out), `setHttpProxy(127.0.0.1:8080)`.
  - `LocalProxy.kt`: step 1 pass-through HTTP proxy on 127.0.0.1:8080 (loopback
    only). CONNECT tunnels and plain-HTTP forwarding, logs every host. Checks
    nothing: it only proves that traffic arrives.
  - `MainActivity.kt`: Start / Stop / Clear buttons and the log.
  - `EventLog.kt`: in-memory log (300 lines) with listeners.
- Built successfully on 19 Nov 2026:
  `app/build/outputs/apk/debug/app-debug.apk` (2.4 MB, debug-signed).
- First phone test (0.0.1, 21 Nov 2026, mobile data): Chrome showed
  `ERR_PROXY_CONNECTION_FAILED` and the log stayed empty after "Proxy
  listening". So **Chrome does follow the VPN's proxy on mobile data**, but
  could not reach it: `InetAddress.getLoopbackAddress()` is IPv6 `::1` on
  Android, so the proxy listened on [::1]:8080 while apps were told
  127.0.0.1. 0.0.2 binds 127.0.0.1 explicitly and logs the real address.
- **Step 1 PROVEN (0.0.2, 21 Nov 2026):** on mobile data, Wi-Fi off, Chrome
  sends every site through the VPN-set proxy (`HTTPS host:443` lines in the
  log) and pages load. A VPN with only a narrow unused route is enough; no
  default route or packet forwarding needed.

### The step 1 test (owner does it, then reports)

Install the APK by copying it to the phone (owner's preferred way, no adb).
Wi-Fi off → Fingertip → Start → accept the VPN request → browse in Chrome
(example.com, wikipedia.org) → sites must appear in the app log as
`HTTPS host:443`. If yes: browsers follow the VPN's proxy on mobile data and
step 2 builds on it. If the log stays empty while pages load: they bypass it
(possible cause to check first: Android may only apply a VPN's proxy when
the VPN carries a default route; then the VPN would need to route 0.0.0.0/0
and forward packets, a much bigger job).

## Build environment (Windows 11 PC)

- Android Studio at C:\Program Files\Android\Android Studio, bundled Java
  (JBR) **25.0.4**. SDK at %LOCALAPPDATA%\Android\Sdk (platforms android-35,
  android-37.0; build-tools 34.0.0, 36.0.0). No other JDK installed.
- Gradle **9.9.1** (wrapper committed to the folder: gradlew, gradlew.bat,
  gradle/wrapper/gradle-wrapper.jar), Android Gradle plugin **9.5.1** with
  its **built-in Kotlin** (do NOT add the org.jetbrains.kotlin.android
  plugin; AGP 9 rejects it). Bytecode target Java 17 via compileOptions.
- Lessons from the first build: `jvmToolchain(17)` fails (no JDK 17
  installed); Gradle 8.x cannot run on Java 25 (fails with "25.0.4").
- Command-line build (PowerShell):
  `$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"; .\gradlew.bat assembleDebug`
  Builds take ~1.5 min cold. Strip Java 25's "restricted method" warnings
  from output when reading it.
- Docker Desktop is installed (start it with
  `Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"`); the
  owner tends to close it. Go is NOT installed on Windows: Go work so far ran
  in `golang:1.26-alpine` containers. Python is not installed; use Node or
  PowerShell for scripts.
- The shell is Git Bash or PowerShell. In Git Bash, `docker run -v` paths
  need `MSYS_NO_PATHCONV=1`.

## Plan

Strategy changed on 21 Nov 2026: **SANE first, plain DANE as fallback, no
hnsd on the phone.** SANE (Stateless DANE, HIP-0017) lets the phone verify a
site from proofs carried in its own certificate, checked offline against
Handshake tree roots, so verification needs no trusted resolver and no live
lookups. That is what makes a light client possible away from home. Castell
(galetaire/castell) already embeds these proofs for the owner's sites
(e.g. `belikebill`); almost no other Handshake site does yet, hence the
fallback.

1. **Step 1 (done, proven 21 Nov 2026):** prove the VPN-set proxy is used on mobile
   data (above). Neither SANE nor DANE helps if Chrome ignores it: Chrome
   understands neither, so the phone always needs the intercepting proxy
   that re-signs with the local CA.
2. **Step 2: the verifying proxy on the phone.** Replace `LocalProxy` with a
   Go proxy built for Android with gomobile (an .aar). Keep the letsdane
   base and Dit's design (Dit repo, `docker/dane/main.go`) for everything
   except how a site is verified:
   - letsdane **v0.6.1** as a Go library (buffrr/letsdane, Apache-2.0, quiet
     since Feb 2024; last tagged release v0.5.0 has no binaries), with its
     old dependencies (miekg/dns, golang.org/x/*) upgraded: Dit uses Go 1.26
     and latest deps, govulncheck clean.
   - Local CA with **name constraints excluding every ICANN TLD** (IANA list
     https://data.iana.org/TLD/tlds-alpha-by-domain.txt, refreshed at build;
     plus special-use names local, localhost, onion, test, invalid, example,
     internal, alt, home.arpa) so a leaked CA cannot sign gmail.com. Dit's
     `main_test.go` proves leaves for www.com are rejected.
   - Settings: Validity 1h, SkipNameChecks false, Constraints = the ICANN
     list (ICANN names are tunnelled without any checks).
   - No PAC with a VPN proxy, so everything goes through the proxy: ICANN
     traffic must be passed through efficiently.
   - **Verifier, in order:**
     1. **SANE:** if the site's certificate carries the HIP-17 proofs (urkel
        proof of the name + DNSSEC chain to TLSA), verify them offline
        against the stored tree roots. Strongest result, no lookups; only
        the untrusted address lookup, over encrypted DNS.
     2. **SANE with proofs from a service:** if the certificate carries
        none, fetch the same two proofs from a public proof service
        (sdaneproofs.htools.work, sdaneproofs.woodburn.au) and verify them
        the same way. Just as strong (the service is not trusted, every step
        is checked), but the service learns the name. Services answer HTTP
        500 for names without TLSA, and fail for some DNS hosts.
     3. **Fallback, plain DANE over DoH** (hnsdoh.com): TLSA from a public
        Handshake resolver, trusting its answer. Weaker (trusts the
        resolver, which also sees the names), but works anywhere.
     4. **Strict mode** (user option): no step 3, refuse what steps 1–2
        cannot verify.

     Every SANE result must end with Dit's "key" step: the certificate the
     site serves matches a proven TLSA record (usage 3, or 2 on the chain),
     otherwise proofs could be replayed on another server. The app shows per
     site which path verified it ("SANE", "SANE via service", "via
     resolver").
   - **Where the SANE code comes from: Dit's checker** (Dit repo,
     `docker/dane/`, v0.6.0, 21 Nov 2026), ~1,000 lines of Go to move into
     the gomobile library: `urkel.go` (own MIT port of handshake-org/urkel's
     proof verifier; nodech/go-hsd-utils has no licence, do not use),
     `hns.go` (name state, DS from hsd resource records), `dnssecchain.go`
     (offline chain check, only trust anchor = the on-chain DS, delegation
     to child zones supported), `sitecert.go` (proofs from the served
     certificate + the key step). Pure Go + miekg/dns, no cgo, so it should
     build for Android. `check.go` is the CLI/JSON wrapper: keep the step
     list, drop the CLI. Tests with real proofs in `testdata/` (fixed date
     20 Nov 2026) come along. Already VERIFIED on the Umbrel: `belikebill`
     and `just.belikebill` from their own certificates, `nathan.woodburn`
     and `hnsdoh` via the services.
   - Not randomlogin/sane or htools-org/stateless-dane: unmaintained since
     2024, usage 3 only, and sane still looks up TLSA via a resolver.
3. **Step 3: tree-root sync**, the open design question (it replaces
   "hnsd or DoH?"). A tree root changes every 36 blocks (~6 h). Proof
   services and Castell anchor to the root from ~8 days ago (HIP-17's 32nd
   most recent), so the phone needs **about two weeks of roots** (Dit keeps
   16 days and refuses roots older than 15; a 7-day window fails). That is
   ~64 roots, a few KB, but their source sets the trust model. (Dit gets
   them from its own hnsd's header log, `docker/web/lib/treeroots.js`; the
   phone has no hnsd.) Options:
   - (a) Download them from one server (owner's or Dit's): simplest, but
     that server is trusted, much weaker than proof of work.
   - (b) Sync only block headers from Handshake peers (SPV, no name
     queries): keeps the proof-of-work trust model, leaks no names, costs
     some data and peer connections, far less than full hnsd.
   - (c) Fetch headers from any server and check them on the phone: two
     weeks is ~2,000 headers, roughly 0.5 MB, checked for proof of work and
     for linking into one chain from a checkpoint built into the app.
     Trust close to (b) without peer connections. Probably the best fit.

### What Castell embeds (checked 21 Nov 2026, Castell 0.4.0, `docker/web/lib/sdane.js`)

- **Yes, the full chain.** Two non-critical extensions:
  - OID 1.3.6.1.4.1.54392.5.1620: the Urkel proof of the TLD (its on-chain
    state with its DS records), fetched from the proof services.
  - OID 1.3.6.1.4.1.54392.5.1621: the DNSSEC chain. 2 bytes port (443), 2
    bytes lifetime (0), then wire-format RRs: TLSA set + its RRSIGs, the
    zone's DNSKEY set + its RRSIGs, and the DS set. Castell builds it from
    the site's own DNS host and checks every signature first.
- So a client can verify a Castell site with **no lookups at all** apart
  from the untrusted address lookup. Castell refreshes the proofs daily.
- Limit: Castell builds chains only for names inside the TLD's zone, not for
  delegated subzones (Dit's verifier handles delegation if another site
  sends one).

### Open questions to check before building step 2

- **HIP-17 is a draft:** its certificate extension IDs are "to be defined".
  If they change, Castell and this app change together (owner controls
  both).
- hnsd for Android (pinned commit 0cb70e5, with the patch below) is **no
  longer planned**; keep the notes in case option (b) above ends up reusing
  hnsd's header sync.

## Lessons from Dit that apply here

- **hnsd + recent unbound bug:** hnsd answers a missing name with an NSEC
  "`. → .`" (whole root zone empty, 24 h). With unbound's aggressive-nsec (on
  by default since 1.15) one lookup of any missing name makes unbound deny
  every Handshake name for 24 h. Dit builds hnsd with
  `sed -i 's|ub_ctx_set_option(ns->ub, "qname-minimisation:", "yes");|& ub_ctx_set_option(ns->ub, "aggressive-nsec:", "no");|' src/rs.c`.
  Any hnsd build here needs the same patch. Upstream fix handshake-org/hnsd#86
  is unmerged since 2022.
- **Certificates on Android:** Chrome trusts user-installed CAs; most other
  apps do not. Firefox for Android needs "Use third party CA certificates"
  (Settings → About Firefox → tap the logo 5× → Secret Settings) and DNS over
  HTTPS off.
- **Single-word names** (`belikebill/`): fine on Android; Windows never sends
  them to DNS (irrelevant here, but explains desktop behaviour).
- A trailing dot (`name.`) breaks letsdane: SNI "name." != TLSA domain.
- Test sites that use DANE (TLSA 3 1 1): `nathan.woodburn`, `hnsdoh`,
  `just.belikebill`, `belikebill`. `woodburn` exists but its own server has
  answered 502 since 17 Nov 2026.
- hnsdoh.com has no DNS over TLS (port 853 closed), so Android Private DNS
  cannot point at it.
- No mobile Handshake/SANE/letsdane client was found on GitHub (searched
  18 Nov 2026): this is new ground.

## Working with the owner

- Explains goals in plain language; prefers concrete step-by-step
  instructions for anything done on the phone or in Android Studio.
- Installs test builds by copying the APK to the phone (no USB debugging).
- Decides on releases/commits explicitly: ask before committing, pushing or
  creating a GitHub repository.
