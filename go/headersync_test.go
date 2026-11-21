package main

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The built-in checkpoint must be a real, fully valid stretch of the chain:
// re-check every header after the first window (work, retargeting, time),
// and compare with tree roots that the owner's own hnsd (Dit, on the
// Umbrel) synced independently on 21 Nov 2026 (Dit's CLAUDE.md).
func TestBuiltinCheckpoint(t *testing.T) {
	first, headers, err := decodeWindow(builtinCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != checkpointLength {
		t.Fatalf("%d headers, want %d", len(headers), checkpointLength)
	}
	chain, err := newHeaderChain(first, headers[:minWindow])
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range headers[minWindow:] {
		if err := chain.connect(h, time.Unix(int64(h.Time), 0)); err != nil {
			t.Fatalf("checkpoint does not verify: %v", err)
		}
	}
	for height, prefix := range map[uint32]string{355465: "0e7787ce", 355537: "1ca1b6e7"} {
		e := chain.at(height)
		if e == nil {
			t.Errorf("block %d not in the checkpoint", height)
			continue
		}
		if got := hex.EncodeToString(e.header.TreeRoot[:]); !strings.HasPrefix(got, prefix) {
			t.Errorf("block %d tree root %s, Dit's hnsd saw %s…", height, got, prefix)
		}
	}
	tip := chain.tip()
	t.Logf("checkpoint verifies: blocks %d-%d, %d distinct tree roots, last %s", first, tip.height, len(chain.roots), hashHex(tip.hash))
}

// A tampered header in a window must be refused
func TestHeaderChainRefusesBadHeaders(t *testing.T) {
	first, headers, err := decodeWindow(builtinCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	base := headers[:minWindow]
	next := *headers[minWindow]
	now := time.Unix(int64(next.Time), 0)

	cases := map[string]func(h *header){
		"changed tree root": func(h *header) { h.TreeRoot[0] ^= 1 },
		"easier target":     func(h *header) { h.Bits = powBits },
		"old time":          func(h *header) { h.Time = base[0].Time },
		"wrong parent":      func(h *header) { h.PrevBlock[0] ^= 1 },
	}
	for name, change := range cases {
		chain, err := newHeaderChain(first, base)
		if err != nil {
			t.Fatal(err)
		}
		h := next
		change(&h)
		if err := chain.connect(&h, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	chain, _ := newHeaderChain(first, base)
	if err := chain.connect(&next, now); err != nil {
		t.Errorf("the real next header must connect: %v", err)
	}
}

func testSync(t *testing.T) *headerSync {
	t.Helper()
	s, err := newHeaderSync(filepath.Join(t.TempDir(), "headers.bin"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	// "Now" is just after the checkpoint, as if synced
	s.now = func() time.Time { return time.Unix(int64(s.chain.tip().header.Time), 0).Add(10 * time.Minute) }
	s.syncedAt = s.now()
	s.lastAttempt = s.now() // no resync attempts in tests
	return s
}

func TestCheckRoot(t *testing.T) {
	s := testSync(t)
	ctx := context.Background()
	known := s.chain.at(s.chain.tip().height - 1100).header.TreeRoot // ~8 days old
	if how, err := s.checkRoot(ctx, known[:]); err != nil || !strings.Contains(how, "checked against") {
		t.Errorf("a root of the chain: %q %v", how, err)
	}
	unknown := known
	unknown[0] ^= 1
	if _, err := s.checkRoot(ctx, unknown[:]); !errors.Is(err, errUnknownRoot) {
		t.Errorf("an unknown root: %v", err)
	}
	old := s.chain.entries[0].header.TreeRoot // ~16.7 days old
	if _, err := s.checkRoot(ctx, old[:]); err == nil {
		t.Error("a root older than 15 days must be refused")
	}
	s.syncedAt = time.Time{}
	if _, err := s.checkRoot(ctx, known[:]); !errors.Is(err, errHeadersNotSynced) {
		t.Errorf("before any sync: %v", err)
	}
}

func TestAcceptUsesTheVerifiedChain(t *testing.T) {
	s := testSync(t)
	o := newOnChain([]string{"https://a.example", "https://b.example"}, nil)
	o.checkRoot = s.checkRoot
	ctx := context.Background()
	known := s.chain.at(s.chain.tip().height - 1100).header.TreeRoot
	fake := known
	fake[5] ^= 0xff
	value := []byte{3, 'f', 'o', 'o', 0, 0}

	// One service with a known root is enough, even if another lies
	rec, err := o.accept(ctx, "foo", []*provenRecord{{"https://a.example", fake[:], value}, {"https://b.example", known[:], value}}, []error{nil, nil})
	if err != nil || !strings.Contains(rec.How, "checked against") || !strings.Contains(rec.How, "b.example") {
		t.Errorf("known root: %+v %v", rec, err)
	}
	// Agreeing services with a root the chain does not have: refused
	if _, err := o.accept(ctx, "foo", []*provenRecord{{"https://a.example", fake[:], value}, {"https://b.example", fake[:], value}}, []error{nil, nil}); err == nil {
		t.Error("a root outside the verified chain must be refused, however many services agree")
	}
	// Headers not synced: agreement, labelled as not checked
	s.syncedAt = time.Time{}
	rec, err = o.accept(ctx, "foo", []*provenRecord{{"https://a.example", fake[:], value}, {"https://b.example", fake[:], value}}, []error{nil, nil})
	if err != nil || !strings.Contains(rec.How, "NOT checked") {
		t.Errorf("not synced: %+v %v", rec, err)
	}
}

func TestSavedWindowIsReused(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "headers.bin")
	s, err := newHeaderSync(file, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	// A saved window that is the checkpoint is not newer: ignored
	os.WriteFile(file, encodeWindow(s.chain.entries), 0o600)
	again, _ := newHeaderSync(file, t.Logf)
	if again.chain.tip().height != s.chain.tip().height {
		t.Error("unexpected tip")
	}
	// Garbage is ignored too
	os.WriteFile(file, []byte("nonsense"), 0o600)
	if _, err := newHeaderSync(file, t.Logf); err != nil {
		t.Errorf("a broken saved file must not stop the start: %v", err)
	}
}

// Syncs from real peers on top of the checkpoint, then resolves a real name
// with every root checked. FINGERTIP_LIVE=1.
func TestHeaderSyncLive(t *testing.T) {
	if os.Getenv("FINGERTIP_LIVE") != "1" {
		t.Skip("set FINGERTIP_LIVE=1 to sync from Handshake peers")
	}
	s, err := newHeaderSync(filepath.Join(t.TempDir(), "headers.bin"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := s.sync(ctx); err != nil {
		t.Fatal(err)
	}
	o := newOnChain(defaultServices, nil)
	o.client = httpClientForTests()
	o.checkRoot = s.checkRoot
	for _, tld := range []string{"belikebill", "woodburn"} {
		rec, err := o.lookup(ctx, tld)
		if err != nil || !rec.Exists || !strings.Contains(rec.How, "checked against") {
			t.Errorf("%s: %+v %v", tld, rec, err)
			continue
		}
		t.Logf("%s: %s", tld, rec.How)
	}
}
