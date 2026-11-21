# Runs zsp, Zapstore's publishing tool, in Docker (it has no Windows build).
# Run it yourself in a terminal: some steps ask for secrets.
#
#   .\scripts\zapstore.ps1             the wizard: once, to claim the app
#                                      (links the APK signing key to your
#                                      Nostr key). The keystore folder is
#                                      mounted read-only at /keys.
#   .\scripts\zapstore.ps1 check       what Zapstore sees for this app
#   .\scripts\zapstore.ps1 publish     publish the latest GitHub release
#
# The Nostr signer: set $env:SIGN_WITH to a bunker:// link (from Amber or
# another remote signer; recommended) or an nsec1... key before running, or
# type it when asked. It is passed to the container from the environment,
# never written to a file or put on the command line.

# Not "Stop": PowerShell 5.1 would treat docker's stderr as a failure; exit
# codes are checked instead
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
# The tag changes whenever the Dockerfile does, so the image is rebuilt
$image = "shakeportal-zsp:2.0.1-3"
$keys = Join-Path $env:USERPROFILE ".shakeportal"

docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Building $image (once)..."
    docker build -t $image (Join-Path $root "scripts\zapstore")
    if ($LASTEXITCODE -ne 0) { throw "docker build failed (is Docker Desktop running?)" }
}

$command = if ($args.Count -gt 0) { $args[0] } else { "" }
$needsSigner = $command -eq "" -or $command -eq "publish"
# Says what kind of value it is without showing it
function Get-SignerKind([string]$value) {
    if ($value -match '^(nsec1|bunker://)') { return "ok" }
    if ($value -eq "") { return "nothing was entered (the paste may not have landed)" }
    if ($value -match '^npub1') { return "that is your public key (npub1...); the signer is the bunker:// link or the nsec1... key" }
    if ($value -match '^nostrconnect://') { return "that is a nostrconnect:// link; zsp needs a bunker:// link" }
    return "it starts with neither bunker:// nor nsec1 ($($value.Length) characters)"
}

if ($needsSigner) {
    $signer = if ($env:SIGN_WITH) { $env:SIGN_WITH } else { "" }
    for ($try = 0; ; $try++) {
        # Spaces, line breaks and quotes from copying are dropped
        $signer = $signer.Trim().Trim('"', "'").Trim()
        $kind = Get-SignerKind $signer
        if ($kind -eq "ok") { break }
        if ($try -gt 0 -or $env:SIGN_WITH) { Write-Host "Not a Nostr signer: $kind" -ForegroundColor Yellow }
        if ($try -ge 3) { throw "No valid Nostr signer given" }
        $secure = Read-Host -AsSecureString "Nostr signer (bunker://... or nsec1...; the typing stays hidden)"
        $signer = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    }
    $env:SIGN_WITH = $signer
}

$run = @("run", "--rm", "-i", "-v", "${root}:/src", "-w", "/src", "-e", "SIGN_WITH")
if ([Environment]::UserInteractive -and -not [Console]::IsOutputRedirected) { $run += "-t" }
if ($needsSigner) {
    # The preview page, http://localhost:17008/, opened in the PC's browser:
    # publishing waits for its Approve button
    $run += @("-p", "127.0.0.1:17008:17009")
}
if ($command -eq "" -and (Test-Path $keys)) {
    # For the claim: the wizard asks for /keys/shakeportal-release.p12 and its
    # password (storePassword in keystore.properties next to it)
    $run += @("-v", "${keys}:/keys:ro")
}
& docker @run $image @args
exit $LASTEXITCODE
