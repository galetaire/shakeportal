package main

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// Real proofs for nathan.woodburn, fetched from sdaneproofs.htools.work on
// 20 Nov 2026 (testdata/nathan.woodburn.{urkel,dnssec}.hex)
func loadHex(t *testing.T, file string) []byte {
	t.Helper()
	text, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestUrkelProofOfWoodburn(t *testing.T) {
	proofs, err := decodeUrkelBlob(loadHex(t, "testdata/nathan.woodburn.urkel.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) == 0 {
		t.Fatal("no proofs")
	}
	p := proofs[0]
	if p.proof.kind != proofExists {
		t.Fatalf("proof type %s, want exists", proofTypeNames[p.proof.kind])
	}
	value, err := p.proof.verify(p.root, nameKey("woodburn"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	ns, err := decodeNameState(value)
	if err != nil {
		t.Fatal(err)
	}
	if ns.name != "woodburn" {
		t.Errorf("proven name %q, want woodburn", ns.name)
	}
	res, err := parseResource(ns.resource)
	if err != nil {
		t.Fatal(err)
	}
	ds := res.DS
	if len(ds) == 0 {
		t.Fatal("no DS records in the proven resource")
	}
	if len(res.NS)+len(res.Glue)+len(res.Synth) == 0 {
		t.Fatal("no nameservers in the proven resource")
	}
	t.Logf("root %x, depth %d, %d nodes, DS %v, NS %v, glue %v, synth %v", p.root, p.proof.depth, len(p.proof.nodes), ds, res.NS, res.Glue, res.Synth)

	// The same proof must fail for another name, another root, or a changed value
	if _, err := p.proof.verify(p.root, nameKey("nb")); err == nil {
		t.Error("proof verified for the wrong name")
	}
	otherRoot := append([]byte{}, p.root...)
	otherRoot[0] ^= 1
	if _, err := p.proof.verify(otherRoot, nameKey("woodburn")); err == nil {
		t.Error("proof verified against the wrong root")
	}
	p.proof.value[len(p.proof.value)-1] ^= 1
	if _, err := p.proof.verify(p.root, nameKey("woodburn")); err == nil {
		t.Error("proof verified with a changed value")
	}
}
