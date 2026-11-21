package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestCompactRoundTrip(t *testing.T) {
	for _, bits := range []uint32{0x1c00ffff, 0x1903a30c, 0x19015f53, 0x1a0377ae, 0x207fffff} {
		if got := toCompact(fromCompact(bits)); got != bits {
			t.Errorf("toCompact(fromCompact(%08x)) = %08x", bits, got)
		}
	}
	if fromCompact(0x1c00ffff).Cmp(powLimit) != 0 {
		t.Error("the starting bits must be the PoW limit")
	}
	if toCompact(big.NewInt(0x80)) != 0x02008000 {
		t.Error("a high mantissa bit must move into the exponent")
	}
}

func TestHeaderEncodeDecode(t *testing.T) {
	raw := make([]byte, headerSize)
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	h, err := decodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(h.encode()) != hex.EncodeToString(raw) {
		t.Error("encode(decode(x)) != x")
	}
}

// hsd's last hardcoded checkpoint (lib/protocol/networks.js v8.0.0)
const (
	hsdCheckpointHeight = 258026
	hsdCheckpointHash   = "0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95"
)

// Asks real peers for the 2000 headers after hsd's checkpoint: they must
// link to it and to each other, with valid proof of work. This checks the
// header hashing against the real chain. SHAKEPORTAL_LIVE=1.
func TestHeadersFromPeersLive(t *testing.T) {
	if os.Getenv("SHAKEPORTAL_LIVE") != "1" {
		t.Skip("set SHAKEPORTAL_LIVE=1 to ask Handshake peers")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	peers := seedPeers(ctx)
	t.Logf("%d peers from the DNS seeds", len(peers))
	var cp [32]byte
	raw, _ := hex.DecodeString(hsdCheckpointHash)
	copy(cp[:], raw)
	for _, addr := range peers {
		p, err := dialPeer(ctx, addr)
		if err != nil {
			t.Logf("%v", err)
			continue
		}
		headers, err := p.getHeaders([][32]byte{cp})
		p.close()
		if err != nil || len(headers) == 0 {
			t.Logf("%s: no headers (%v)", addr, err)
			continue
		}
		prev := cp
		for i, h := range headers {
			if h.PrevBlock != prev {
				t.Fatalf("header %d does not link", hsdCheckpointHeight+1+i)
			}
			prev = h.hash()
			if !verifyPOW(prev, h.Bits) {
				t.Fatalf("header %d: bad proof of work (hash %x)", hsdCheckpointHeight+1+i, prev)
			}
		}
		t.Logf("%s: %d headers after the checkpoint link and have valid work; last %x", addr, len(headers), prev)
		return
	}
	t.Fatal("no peer sent headers")
}
