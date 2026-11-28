# ShakePortal (formerly fingertip-android): project context

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

## State: 0.3.0 proven on the phone (21 Nov 2026), as ShakePortal

Steps 1–3 are proven on the phone (0.2.0, 21 Nov 2026): on mobile data,
Handshake sites load in Chrome, checked with DANE, with every tree root
checked against block headers the phone synced and verified itself.

0.3.0 (21 Nov 2026, proven on the phone the same day: the four test sites load on mobile data, Stateless DANE and DNSSEC-from-the-chain both shown ✓, CA shown as installed) adds: Urkel proofs from Handshake peers
(proof services only as fallback), Stateless DANE from the site's own
certificate, per-site results and the CA fingerprint on screen, and a
refreshed checkpoint.

- **0.3.0 Go additions:**
  - `peerproof.go`: one kept peer connection; `getproof` for nameKey(tld)
    under the **verified tip's tree root** (hnsd's approach), proof
    verified against it; tried first by `onChain.lookup` (`fromPeer`),
    services after. Live: records for belikebill/woodburn from a peer,
    root of block 356725.
  - `sane.go` + `dnssecchain.go` (Dit's verifier, dsMatches adapted):
    `LookupTLSA` first fetches the site's certificate (address from our
    resolver, TLS without verification) and, if it has OIDs
    1.3.6.1.4.1.54392.5.1620/1621, checks the Urkel proof's root with
    `checkRoot`, the proof, then the chain from the on-chain DS. Result
    cached 1 h per name (also "no proofs"). The key step is letsdane's own
    TLSA check when it dials. Falls back to the nameserver path.
  - `report.go`: `@site <name> <status> <detail>` lines (statuses
    verified-sane, verified, verified-unchecked, not-dane, unsigned,
    refused, failed, and plain-http from `plainhttp.go`: plain http:// requests
    to Handshake names, watched around letsdane's handler), printed only on change; `bogusError` separates DNSSEC
    failures (refused) from network ones (failed); a log filter turns
    letsdane's "[WARN] ... dane authentication failed" into "refused".
  - Tests: Dit's chain tests (nathan.woodburn, fixed date 20 Nov 2026),
    belikebill.crt proves itself offline against the checkpoint roots
    (block 355465), a copy with another key does not match the TLSA, a
    changed chain byte and another name are refused, LookupTLSA asks no
    nameserver for a SANE site, report dedupe + letsdane parsing.
- **0.3.0 Kotlin:** `SiteResults.kt` (newest 8 of up to 30 sites, ✓ ⚠ – ✗),
  DaneProxy routes `@site` lines there; `caFingerprint()` from ca.crt;
  MainActivity shows the fingerprint, "Handshake sites" and "Log".
- **0.3.0 emulator test:** belikebill and just.belikebill "verified from
  its own certificate" (roots of blocks 355465 and 355537), nathan.woodburn
  and hnsdoh "verified with DNSSEC from the chain" (record proven by a
  peer), woodburn verified (its server itself answers 502), an unknown
  name "failed: no such name on the Handshake chain".

- Repo: ~/Documents/GitHub/ShakePortal, branch main, public on GitHub
  (github.com/galetaire/ShakePortal, created 21 Nov 2026 as fingertip-android, renamed the same day). Commit/push
  only when the owner asks.
- Package `io.github.galetaire.shakeportal` (was io.github.galetaire.fingertip until 21 Nov 2026: a new id, so the old app must be uninstalled), app name **"ShakePortal"** (renamed from Fingertip 21 Nov 2026; icon from art/icon.png as an adaptive icon, rebuilt with scripts/make-icon.ps1; Save CA writes ShakePortal-CA.crt; new CAs are "ShakePortal DANE (phone)", an existing CA is kept with its old name "Fingertip DANE (phone)"), version
  0.3.2 (versionCode 7; 0.3.1 changed the icon, 0.3.2 added plain-HTTP sites and the portal wording), minSdk 29, targetSdk/compileSdk 35. No Android
  libraries: framework + Kotlin only, UI built in code.
- **Release signing (21 Nov 2026, for Zapstore):** keystore
  `C:\Users\Ismae\.shakeportal\shakeportal-release.p12` (PKCS12, alias
  `shakeportal`, RSA 4096, 10,000 days, DN "CN=ShakePortal, O=galetaire",
  certificate SHA-256 71f303cc60c24e3d8625b383935709877da8c3e0c228b07ce96af43f62b3fe54).
  Release builds are arm64-v8a only (`ndk.abiFilters` in the release build
  type; Zapstore takes one arm64 APK); debug keeps x86_64 for the emulator.
  Its path and random password are in `keystore.properties` (project root,
  git-ignored; a copy sits next to the keystore). app/build.gradle.kts signs
  `assembleRelease` with it when that file exists. Never print the password;
  never commit the keystore. The release APK (signature v2, arm64-v8a +
  x86_64) passed the four test sites on the emulator. Losing the key means
  no more updates on Zapstore under the same listing.
- **Zapstore:** `zapstore.yaml` (repository + `match` on
  `ShakePortal-X.Y.Z-arm64-v8a.apk` release assets, listing text, art/icon.png,
  art/screenshot-1/2.png, CHANGELOG.md as release notes). zsp 2.0.1 has no
  Windows build: `scripts/zapstore.ps1` runs it in Docker (image
  `shakeportal-zsp:2.0.1` from scripts/zapstore/Dockerfile, Debian, binary
  checked against zapstore.dev's SHA-256 1ef5373f…5b38). SIGN_WITH comes from
  the environment or a hidden prompt; never handle it, the nsec or the
  keystore password as an agent: zsp's own docs say the claim is done by
  hand. `zsp check <apk>` on the 0.3.0 release APK: ok, no warnings, next
  step "Prove the app is yours" (claim, requires_human). State 21 Nov 2026:
  0.3.0 published and listed on Zapstore 21 Nov 2026 (owner claimed it, proof valid to 20 Nov 2028; the preview page at localhost:17008 must be approved in the browser). 0.3.1 published the same day, 0.3.2 on 28 Nov 2026 (owner ran zsp publish; check shows published_version_code 7).
- **Step 1 PROVEN (0.0.2, 21 Nov 2026, real phone):** on mobile data, Wi-Fi
  off, Chrome sends every site through the VPN-set proxy and pages load. A
  VPN with only a narrow unused route is enough. (0.0.1 failed with
  `ERR_PROXY_CONNECTION_FAILED`: `InetAddress.getLoopbackAddress()` is IPv6
  `::1` on Android, so bind 127.0.0.1 explicitly.)
- Kotlin (app/src/main/java/io/github/galetaire/shakeportal/):
  - `ProxyVpnService.kt`: VPN (10.111.0.1/32, route only 10.111.0.0/24,
    `addDisallowedApplication(packageName)`, `setHttpProxy(127.0.0.1:8080)`).
    Starts DaneProxy with the network's DNS servers (LinkProperties of the
    app's default network, which is the real one since the app is outside
    the VPN) and restarts it when they change.
  - `LocalProxy.kt`: the proxy apps get, 127.0.0.1:8080. ICANN names and IPs
    pass straight through (resolved by Android, so Private DNS applies);
    Handshake names are forwarded, request bytes as received, to the DANE
    proxy on 127.0.0.1:8081. Logs `HTTPS host` / `HNS host → DANE proxy`.
  - `IcannTlds.kt`: Handshake name = TLD not in assets/icann-tlds.txt and not
    special-use.
  - `DaneProxy.kt`: runs `libshakeportald.so` from nativeLibraryDir with
    ProcessBuilder (`-listen 127.0.0.1:8081 -data files/dane -tlds ... -dns
    ...`, env SSL_CERT_DIR=/apex/com.android.conscrypt/cacerts:/system/etc/
    security/cacerts), its output into the log; stops it by closing stdin.
  - `MainActivity.kt`: Start / Stop / Clear / Save CA certificate (copies
    files/dane/ca/ca.crt to Downloads as ShakePortal-CA.crt via MediaStore;
    apps cannot install CAs themselves since Android 11) and the log.
  - Manifest: INTERNET, ACCESS_NETWORK_STATE (needed for LinkProperties).
- Go (`go/`, module github.com/galetaire/ShakePortal/go, package main,
  letsdane v0.6.1, deps upgraded with `go get -u`):
  - `main.go`: flags, name-constrained CA in <data>/ca (from Dit), letsdane
    handler (Validity 1h, Constraints = ICANN list), loopback-only listener,
    `-dns` servers for its own lookups, exits when stdin closes.
  - `onchain.go`: TLD record from the proof services
    (`<service>/proofs/<tld>?urkel`, sdaneproofs.htools.work and
    sdaneproofs.woodburn.au), Urkel proof verified against the root it
    names, and **the root must be a tree root of the verified header chain,
    at most 15 days old** (`accept` + `checkRoot`; one service is enough,
    a lying one is outvoted by the chain). Only while headers are not synced
    (`errHeadersNotSynced`) the old rule applies, labelled "NOT checked":
    every answering service must give the same root and record. An unknown
    root triggers a resync (at most once a minute). Cached 1 h (absence
    10 min).
  - Step 3 (block headers), ported from hsd v8.0.0 (MIT):
    - `header.go`: 236-byte header, block hash = hsd powHash
      (BLAKE2b-512/SHA3-256/BLAKE2b-256 over the preheader, XOR mask),
      compact targets, work.
    - `headerchain.go`: window of verified headers; `connect` checks link,
      PoW, exact retarget (chain.js getTarget/retarget: 144-block window,
      median-of-3 "suitable" blocks, clamp 36–576 spacings), median time of
      11, at most 2 h in the future. Keeps 3000 headers, tree-root index.
    - `p2p.go`: hsd P2P over plain TCP 12038 (magic 1533997779, 9-byte
      frame, version/verack, getheaders/headers ≤2000, ping/pong); peers
      from the DNS seeds hs-mainnet.bcoin.ninja and seed.htools.work.
    - `headersync.go`: loads the saved window (<data>/headers.bin) or the
      built-in checkpoint, syncs every 30 min (2 min after failure), asks
      up to 8 peers at once and uses the first 2 that answer (most nodes
      never answer getheaders: pruned or syncing), switches to a fork with
      more work, saves the window.
    - `checkpoint.go` + `checkpoint.bin` (committed, 566 KB): 2400 headers,
      blocks 354327–356726 (refreshed for 0.3.0; last 2026-11-21 08:47
      UTC, hash 000000000000000ee3b791c81bd45ded18ad3dbc1d9c6aae818bfa58975f8580).
      Made by `shakeportald -make-checkpoint` (`build-go.ps1 -Checkpoint`):
      from hsd's checkpoint 225000, ~130k headers all fully verified, must
      pass hsd's 258026; carries on across peers that stop answering. The
      offline test re-verifies it and matches two roots Dit's own hnsd saw
      (355465 0e7787ce…, 355537 1ca1b6e7…). Refresh it now and then: the
      first sync after install downloads everything since it (~34 KB/day).
  - `resolver.go`: letsdane's Resolver interface. Own iterative,
    non-recursive resolver from the on-chain nameservers (GLUE/SYNTH/NS,
    `_<base32hex>._synth.` names), follows referrals, validates DNSKEY from
    the on-chain DS, child DS from the parent, answers from the zone keys;
    a signed zone that fails is an error (fail closed). NSEC denial and
    DS-less delegations are not proven: they only make answers insecure.
  - `hns.go` (name state + resource with NS/glue/synth), `urkel.go` (Dit's
    MIT port), `dnssec.go` (verifySet/dsMatches from Dit).
  - Tests: CA constraints, TLD list, resource parsing, root agreement, an
    in-memory signed TLD with delegation (tampered answer, stripped
    signature, wrong DS all refused), and `TestResolverLive`
    (SHAKEPORTAL_LIVE=1): belikebill, just.belikebill, nathan.woodburn and
    hnsdoh all get a TLSA proven from the on-chain DS (21 Nov 2026).
- **Emulator test (21 Nov 2026, Android 17 x86_64):** app starts the Go
  binary (no seccomp problem with a static GOOS=linux binary), creates the
  CA; a probe client through 127.0.0.1:8080 got all four test sites with
  certificates issued by "Fingertip DANE (phone)" and HTTP 200, example.com
  with its real certificate. Save CA writes Downloads/Fingertip-CA.crt
  (22 KB: the ~1,440 excluded names).
- **hnsdoh.com's DoH was down on 21 Nov 2026** (502 from its openresty for
  every query), and so were all other public Handshake DoH servers tried
  (query.hdns.io 500, doh.hnsdns.com 503, easyhandshake.com, hnsns.net,
  doh.hns.is). That is why the app resolves names itself.

- **Step 2 PROVEN on the phone (0.1.0, 21 Nov 2026):** after installing
  Fingertip-CA.crt, Handshake sites load properly in Chrome on mobile data.
- **Step 3 tests (21 Nov 2026):** live, 2000 headers from a peer link to
  hsd's checkpoint; the checkpoint run verified ~130k headers (retarget
  port exact); live sync from the checkpoint to the tip took 24 s (12 peers
  from the seeds, 1 answered). Emulator (0.2.0): synced to block 356737 in
  ~30 s, then all four test sites "TLSA proven from the on-chain DS (root
  b368aa321cf6… is block 355573's, 195h old, checked against 2413 synced
  headers)"; Stop/Start reuses the saved headers.

### The step 2 test (owner did it, 21 Nov 2026)

Install the new APK over the old one. Start → Save CA certificate → install
it (Settings → Security & privacy → More security settings → Encryption &
credentials → Install a certificate → CA certificate → Fingertip-CA.crt).
Then on mobile data in Chrome: `https://belikebill/`, `https://nathan.woodburn/`,
`https://hnsdoh/`, `https://just.belikebill/` must load without warnings,
and the log must show `TLSA proven from the on-chain DS`. Chrome may need
the trailing slash for single-word names.

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
- Go program for the app: `.scriptsuild-go.ps1` (`-Live` adds the
  network tests, `-Update` upgrades deps) runs scripts/build-go.sh in
  golang:1.26-alpine with the module cache in the `shakeportal-gomod` volume.
  Run it before gradlew whenever go/ changes; its outputs are git-ignored.
  PowerShell 5.1 mangles quotes passed to docker, hence the .sh file.
- Emulator for testing (owner tests on the real phone): AVD
  `Medium_Phone_API_37.0` (Android 17, x86_64, WHPX works):
  `emulator -avd Medium_Phone_API_37.0 -no-window -no-audio -no-boot-anim
  -no-snapshot-save -gpu swiftshader_indirect` in the background, then adb
  (in Git Bash set MSYS_NO_PATHCONV=1). `adb shell appops set
  io.github.galetaire.shakeportal ACTIVATE_VPN allow` skips the VPN dialog;
  find buttons with `uiautomator dump`; `run-as` works (debug build). A
  probe client (CONNECT through 127.0.0.1:8080, TLS verified against the
  app's CA) was built in the scratchpad for the 21 Nov test.
- The shell is Git Bash or PowerShell. In Git Bash, `docker run -v` paths
  need `MSYS_NO_PATHCONV=1`.

## Plan

Strategy as of 21 Nov 2026: **no Handshake resolver and no hnsd on the
phone.** The phone resolves Handshake names itself from on-chain data
(proof services for the TLD's record, the site's own nameservers, DNSSEC
checked locally, tree roots checked against block headers it syncs itself),
which makes plain DANE trustless. Stateless DANE (HIP-17, proofs in the
certificate) can come on top now that the phone has its own tree roots. History: the plan first was letsdane + hnsd, then SANE-first with
DoH fallback; hnsdoh being down on 21 Nov 2026 led to this design.

1. **Step 1 (done, proven 21 Nov 2026):** the VPN-set proxy is used on
   mobile data.
2. **Step 2 (done, proven on the phone 21 Nov 2026, 0.1.0):** the verifying proxy, as
   described in State. Per-site results and the CA fingerprint on screen
   came in 0.3.0. QUIC: Chrome with a proxy uses TCP only; other browsers
   not checked.
3. **Step 3 (done, proven on the phone 21 Nov 2026, 0.2.0): tree roots
   checked, not agreed on.** Done as a mix of (b) and (c): headers from Handshake peers
   (short connections, getheaders only, no name queries), verified like
   hsd does, from a checkpoint built into the app. A root changes every 36
   blocks (~6 h); proofs anchor to the root ~8 days old (HIP-17's 32nd most
   recent), so ~16 days are kept and roots over 15 days are refused.
   Since 0.3.0 the TLD records come from peers (GETPROOF/PROOF, as hnsd
   does) for the tip's root; the proof services are only the fallback.
4. **Step 4 (done, proven on the phone 21 Nov 2026, 0.3.0): Stateless DANE from the
   certificate** (needs step 3): when a
   site's certificate carries the HIP-17 proofs (OIDs
   1.3.6.1.4.1.54392.5.1620/1621; Castell embeds them, see below), verify
   them offline (`sane.go`, Dit's `dnssecchain.go`) instead of asking the nameservers: no lookups beyond the address, and
   works when a site's nameservers are unreachable. Must end with Dit's
   "key" step (served certificate matches the proven TLSA), which letsdane's
   own check provides when the proven TLSA is returned to it.

### What Castell embeds (checked 21 Nov 2026, Castell 0.4.0, `docker/web/lib/sdane.js`)

- **The full chain.** Two non-critical extensions:
  - OID 1.3.6.1.4.1.54392.5.1620: the Urkel proof of the TLD (its on-chain
    state with its DS records), fetched from the proof services.
  - OID 1.3.6.1.4.1.54392.5.1621: the DNSSEC chain. 2 bytes port (443), 2
    bytes lifetime (0), then wire-format RRs: TLSA set + its RRSIGs, the
    zone's DNSKEY set + its RRSIGs, and the DS set. Castell builds it from
    the site's own DNS host and checks every signature first.
- Castell refreshes the proofs daily; chains only for names inside the
  TLD's zone, not delegated subzones.

### Open questions

- **HIP-17 is a draft:** its certificate extension IDs are "to be defined".
  If they change, Castell and this app change together (owner controls
  both).
- The proof services are a dependency for every new TLD (cached 1 h). If
  both are down, Handshake names fail; ICANN browsing is unaffected.
- Expired or revoked names: the name state's other fields (renewal height,
  revoked) are not read yet.
- hnsd for Android is **not planned** (step 3 syncs headers in Go); its
  notes below stay for reference.
- `checkpoint.bin` is binary: keep it out of line-ending conversion
  (.gitattributes) and refresh it with `build-go.ps1 -Checkpoint`.

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
