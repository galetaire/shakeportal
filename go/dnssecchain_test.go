package main

import (
	"strings"
	"testing"
	"time"
)

// Copied from Dit (galetaire/dit, docker/dane). The proofs were fetched on 20 Nov 2026; their signatures are checked as of
// that day, so the test keeps passing after they expire
var proofDay = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func woodburnAnchors(t *testing.T) []hnsDS {
	t.Helper()
	proofs, err := decodeUrkelBlob(loadHex(t, "testdata/nathan.woodburn.urkel.hex"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := proofs[0].proof.verify(proofs[0].root, nameKey("woodburn"))
	if err != nil {
		t.Fatal(err)
	}
	ns, err := decodeNameState(value)
	if err != nil {
		t.Fatal(err)
	}
	res, err := parseResource(ns.resource)
	if err != nil {
		t.Fatal(err)
	}
	return res.DS
}

func TestChainOfNathanWoodburn(t *testing.T) {
	chain := loadHex(t, "testdata/nathan.woodburn.dnssec.hex")
	res, err := verifyChain(chain, "nathan.woodburn", "woodburn", woodburnAnchors(t), proofDay)
	if err != nil {
		t.Fatalf("verify: %v (zones so far %v)", err, res)
	}
	t.Logf("%d records, zones %v, TLSA %v", res.Records, res.Zones, res.TLSA)
	if len(res.TLSA) == 0 || !strings.HasPrefix(res.TLSA[0], "3 1 1 b2f9dde6") {
		t.Errorf("TLSA %v, want 3 1 1 b2f9dde6...", res.TLSA)
	}
}

func TestChainRejectsWrongAnchor(t *testing.T) {
	chain := loadHex(t, "testdata/nathan.woodburn.dnssec.hex")
	anchors := woodburnAnchors(t)
	anchors[0].Digest = append([]byte{}, anchors[0].Digest...)
	anchors[0].Digest[0] ^= 1
	if _, err := verifyChain(chain, "nathan.woodburn", "woodburn", anchors, proofDay); err == nil {
		t.Fatal("chain verified with a DS that is not on chain")
	}
	if _, err := verifyChain(chain, "nathan.woodburn", "woodburn", nil, proofDay); err == nil {
		t.Fatal("chain verified without any anchor")
	}
}

func TestChainRejectsChangedTLSA(t *testing.T) {
	chain := loadHex(t, "testdata/nathan.woodburn.dnssec.hex")
	// The TLSA digest starts b2f9dde62cd9...; flip a bit inside it
	at := strings.Index(strings.ToLower(hexString(chain)), "b2f9dde62cd9") / 2
	if at <= 0 {
		t.Fatal("TLSA digest not found in the test data")
	}
	chain[at] ^= 1
	if _, err := verifyChain(chain, "nathan.woodburn", "woodburn", woodburnAnchors(t), proofDay); err == nil {
		t.Fatal("chain verified with a changed TLSA record")
	}
}

func TestChainRejectsExpiredSignatures(t *testing.T) {
	chain := loadHex(t, "testdata/nathan.woodburn.dnssec.hex")
	later := proofDay.AddDate(1, 0, 0)
	if _, err := verifyChain(chain, "nathan.woodburn", "woodburn", woodburnAnchors(t), later); err == nil {
		t.Fatal("chain verified a year after its signatures were made")
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}
