package main

// The app's built-in checkpoint (checkpoint.bin): the last ~16 days of
// headers at build time, so the phone has the tree roots that proofs use
// (up to ~15 days old) without downloading the chain.
//
// It is made by `shakeportald -make-checkpoint go/checkpoint.bin` (build-go.ps1
// -Checkpoint), which does not trust the peers either: it starts from one of
// hsd's own hardcoded checkpoints, downloads every header from there to the
// tip, checks each one fully (work, retargeting, time), requires the chain
// to pass hsd's last checkpoint, and keeps the tail.

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

//go:embed checkpoint.bin
var builtinCheckpoint []byte

// hsd v8.0.0 lib/protocol/networks.js checkpointMap: where the download
// starts, and the last one, which the downloaded chain must pass
var hsdCheckpoints = map[uint32]string{
	225000: "00000000000000021f0be013ebad018a9ef97c8501766632f017a778781320d5",
	258026: "0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95",
}

const (
	checkpointStart  = 225000
	checkpointLength = 2400 // ~16.7 days of blocks
	// Leave out the newest blocks: they could still be replaced
	checkpointMargin = 12
)

func hash32(s string) [32]byte {
	var h [32]byte
	raw, _ := hex.DecodeString(s)
	copy(h[:], raw)
	return h
}

func makeCheckpoint(ctx context.Context, file string) error {
	peers := seedPeers(ctx)
	if len(peers) == 0 {
		return errors.New("no peers from the DNS seeds")
	}
	// The chain carries over from peer to peer: a peer that stops answering
	// only means the next one continues from there
	var chain *headerChain
	passed, done := false, false
	var lastErr error
	for _, addr := range peers {
		if done {
			break
		}
		p, err := dialPeer(ctx, addr)
		if err != nil {
			log.Printf("%v", err)
			lastErr = err
			continue
		}
		passed, done, chain, err = checkpointFrom(p, chain, passed)
		p.close()
		if err != nil {
			log.Printf("%s: %v", addr, err)
			lastErr = err
		}
	}
	if !done {
		return fmt.Errorf("no peer took the chain to its tip (%v)", lastErr)
	}
	if !passed {
		return errors.New("the chain never reached hsd's last checkpoint")
	}
	tip := chain.tip()
	if age := time.Since(time.Unix(int64(tip.header.Time), 0)); age > 3*time.Hour {
		return fmt.Errorf("the tip (block %d) is %s old: peers not synced", tip.height, age.Round(time.Minute))
	}
	end := len(chain.entries) - checkpointMargin
	window := chain.entries[end-checkpointLength : end]
	if err := os.WriteFile(file, encodeWindow(window), 0o644); err != nil {
		return err
	}
	last := window[len(window)-1]
	log.Printf("checkpoint: blocks %d to %d (%s), last hash %s (tip %d)",
		window[0].height, last.height, time.Unix(int64(last.header.Time), 0).UTC().Format(time.RFC3339), hashHex(last.hash), tip.height)
	return nil
}

// checkpointFrom continues the chain with one peer's headers until the peer
// has no more (done) or fails
func checkpointFrom(p *peer, chain *headerChain, passed bool) (bool, bool, *headerChain, error) {
	var pending []*header
	if chain == nil {
		start := hash32(hsdCheckpoints[checkpointStart])
		first, err := p.getHeaders([][32]byte{start})
		if err != nil {
			return passed, false, nil, err
		}
		if len(first) < minWindow || first[0].PrevBlock != start {
			return passed, false, nil, errors.New("the peer's headers do not start at hsd's checkpoint")
		}
		// The first window is trusted by linking to hsd's checkpoint; from
		// there every header is checked fully
		if chain, err = newHeaderChain(checkpointStart+1, first[:minWindow]); err != nil {
			return passed, false, nil, err
		}
		pending = first[minWindow:]
	}
	for {
		for _, h := range pending {
			if err := chain.connect(h, time.Now()); err != nil {
				return passed, false, chain, fmt.Errorf("at block %d: %w", chain.tip().height+1, err)
			}
			tip := chain.tip()
			if want, ok := hsdCheckpoints[tip.height]; ok && tip.height != checkpointStart {
				if hashHex(tip.hash) != want {
					return passed, false, chain, fmt.Errorf("block %d is not hsd's checkpoint", tip.height)
				}
				passed = true
			}
		}
		if chain.tip().height%20000 < 2000 {
			log.Printf("checked up to block %d", chain.tip().height)
		}
		next, err := p.getHeaders([][32]byte{chain.tip().hash})
		if err != nil {
			return passed, false, chain, err
		}
		if len(next) == 0 {
			return passed, true, chain, nil
		}
		pending = next
	}
}
