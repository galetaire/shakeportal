package main

// Name proofs straight from Handshake peers, as hnsd gets them: ask a full
// node for the Urkel proof of a top-level name under the tree root of our
// own verified tip. The proof is checked against that root, which is in the
// verified chain by construction, so the peer is not trusted. This takes the
// proof services out of the normal path; they stay as a fallback.
//
// One peer connection is kept for proofs and replaced when it fails.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

type proofPeers struct {
	sync *headerSync

	mu   sync.Mutex // one request at a time on the connection
	peer *peer
}

func newProofPeers(s *headerSync) *proofPeers { return &proofPeers{sync: s} }

// prove returns a record proven by a peer for the current tip's root
func (pp *proofPeers) prove(ctx context.Context, tld string) (*provenRecord, error) {
	root, err := pp.sync.tipRoot()
	if err != nil {
		return nil, err
	}
	key := nameKey(tld)
	pp.mu.Lock()
	defer pp.mu.Unlock()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if pp.peer == nil {
			if pp.peer, err = pp.connect(ctx); err != nil {
				return nil, err
			}
		}
		proof, err := pp.peer.getProof(root, key)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", pp.peer.addr, err)
			pp.peer.close()
			pp.peer = nil
			continue
		}
		value, err := proof.verify(root[:], key)
		if err != nil {
			// A peer whose proof does not verify is not used again
			lastErr = fmt.Errorf("%s sent a proof that does not verify: %w", pp.peer.addr, err)
			pp.peer.close()
			pp.peer = nil
			continue
		}
		return &provenRecord{service: "peer " + pp.peer.addr, root: append([]byte{}, root[:]...), value: value}, nil
	}
	return nil, lastErr
}

// connect: the first of up to 8 peers tried at once that completes the
// handshake
func (pp *proofPeers) connect(ctx context.Context) (*peer, error) {
	addrs := pp.sync.peers(ctx)
	if len(addrs) == 0 {
		return nil, errors.New("no peers: the DNS seeds did not answer")
	}
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		p   *peer
		err error
	}
	results := make(chan result, len(addrs))
	slots := make(chan struct{}, 8)
	go func() {
		for _, addr := range addrs {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			go func() {
				defer func() { <-slots }()
				p, err := pp.sync.dial(ctx, addr)
				results <- result{p, err}
			}()
		}
	}()
	var lastErr error
	for got := 1; got <= len(addrs); got++ {
		select {
		case r := <-results:
			if r.err == nil {
				// Close the ones still connecting when they finish (dials
				// not started yet never send)
				left := len(addrs) - got
				go func() {
					for i := 0; i < left; i++ {
						select {
						case more := <-results:
							if more.p != nil {
								more.p.close()
							}
						case <-time.After(30 * time.Second):
							return
						}
					}
				}()
				return r.p, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("no peer connected (%v)", lastErr)
}

// tipRoot: the tree root of the verified tip, if the headers are synced
func (s *headerSync) tipRoot() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syncedAt.IsZero() || s.age(s.chain.tip()) >= maxTipAge {
		return [32]byte{}, errHeadersNotSynced
	}
	return s.chain.tip().header.TreeRoot, nil
}
