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
$image = "shakeportal-zsp:2.0.1"
$keys = Join-Path $env:USERPROFILE ".shakeportal"

docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Building $image (once)..."
    docker build -t $image (Join-Path $root "scripts\zapstore")
    if ($LASTEXITCODE -ne 0) { throw "docker build failed (is Docker Desktop running?)" }
}

$command = if ($args.Count -gt 0) { $args[0] } else { "" }
$needsSigner = $command -eq "" -or $command -eq "publish"
if ($needsSigner -and -not $env:SIGN_WITH) {
    $secure = Read-Host -AsSecureString "Nostr signer (bunker://... or nsec1...)"
    $env:SIGN_WITH = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

$run = @("run", "--rm", "-i", "-v", "${root}:/src", "-w", "/src", "-e", "SIGN_WITH")
if ([Environment]::UserInteractive -and -not [Console]::IsOutputRedirected) { $run += "-t" }
if ($command -eq "" -and (Test-Path $keys)) {
    # For the claim: the wizard asks for /keys/shakeportal-release.p12 and its
    # password (storePassword in keystore.properties next to it)
    $run += @("-v", "${keys}:/keys:ro")
}
& docker @run $image @args
exit $LASTEXITCODE
