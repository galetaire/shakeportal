#!/bin/sh
# Runs inside golang:1.26-alpine (started by build-go.ps1), with the repo at
# /src. LIVE=1 also runs the tests that need the network; UPDATE=1 first
# upgrades every Go dependency; CHECKPOINT=1 rebuilds go/checkpoint.bin
# (the headers built into the app) from Handshake peers.
set -e
cd /src/go
apk add --no-cache git >/dev/null

# IANA's TLD list, fresh: the CA's name constraints and the app's routing
mkdir -p /src/app/src/main/assets
wget -qO /tmp/tlds.txt https://data.iana.org/TLD/tlds-alpha-by-domain.txt
count=$(grep -vc '^#' /tmp/tlds.txt)
[ "$count" -gt 1000 ] || { echo "only $count TLDs downloaded"; exit 1; }
mv /tmp/tlds.txt /src/app/src/main/assets/icann-tlds.txt
echo "ICANN TLDs: $count"

if [ "$UPDATE" = 1 ]; then go get -u ./...; fi
go mod tidy

# The checkpoint is committed; making one downloads and checks ~130,000
# headers from hsd's checkpoint at block 225000 to the tip (a few minutes)
if [ "$CHECKPOINT" = 1 ] || [ ! -s checkpoint.bin ]; then
  [ -e checkpoint.bin ] || : > checkpoint.bin
  go run . -make-checkpoint checkpoint.bin.new
  mv checkpoint.bin.new checkpoint.bin
fi
go vet ./...
gofmt -l . | sed "s/^/needs gofmt: /"
go test ./...
if [ "$LIVE" = 1 ]; then SHAKEPORTAL_LIVE=1 go test -count=1 -v -run Live ./...; fi

for pair in arm64:arm64-v8a amd64:x86_64; do
  out=/src/app/src/main/jniLibs/${pair#*:}
  mkdir -p "$out"
  CGO_ENABLED=0 GOOS=linux GOARCH=${pair%%:*} go build -trimpath -ldflags="-s -w" -o "$out/libshakeportald.so" .
done
ls -l /src/app/src/main/jniLibs/*/libshakeportald.so
