# Builds fingertipd (go/) into the app, in a Go container (Go is not
# installed on this PC). Run it before gradlew whenever go/ changes:
#
#   .\scripts\build-go.ps1            test + build
#   .\scripts\build-go.ps1 -Live      also run the tests that need the network
#   .\scripts\build-go.ps1 -Update    first upgrade every Go dependency
#   .\scripts\build-go.ps1 -Checkpoint  rebuild go/checkpoint.bin (commit it)
#
# Outputs (git-ignored, rebuilt from source):
#   app/src/main/jniLibs/<abi>/libfingertipd.so   the program, one per ABI
#   app/src/main/assets/icann-tlds.txt            IANA's TLD list, fresh
# The program is named lib*.so so that Android installs it next to the app's
# native libraries, the one place an app may run its own executables from.
# The steps themselves are in build-go.sh.
param([switch]$Live, [switch]$Update, [switch]$Checkpoint)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

docker run --rm `
  -v "${root}:/src" `
  -v fingertip-gomod:/go/pkg/mod `
  -e "LIVE=$([int]$Live.IsPresent)" `
  -e "UPDATE=$([int]$Update.IsPresent)" `
  -e "CHECKPOINT=$([int]$Checkpoint.IsPresent)" `
  golang:1.26-alpine sh /src/scripts/build-go.sh
if ($LASTEXITCODE -ne 0) { throw "Go build failed ($LASTEXITCODE)" }
