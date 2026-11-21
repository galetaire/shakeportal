package main

// Keeps the phone's window of verified headers current: from the built-in
// checkpoint (or the window saved by the last run), new headers are fetched
// from Handshake peers every 30 minutes and checked one by one. The tree
// roots in that window are the only roots onchain.go accepts proofs for.
//
// Peers come from hsd's DNS seeds. Up to two peers that answer are asked in
// turn, and a fork with more work replaces the current tip, as in any SPV
// client: a lying peer would need real mining power to fool it.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"time"
)

var (
	errHeadersNotSynced = errors.New("block headers not synced yet")
	errUnknownRoot      = errors.New("tree root is not in the verified chain")
)

const (
	syncEvery       = 30 * time.Minute
	syncRetry       = 2 * time.Minute
	maxTipAge       = 12 * time.Hour // hsd's maxTipAge
	maxProofRootAge = 15 * 24 * time.Hour
	resyncMinGap    = time.Minute
)

type headerSync struct {
	file string
	logf func(string, ...any)
	now  func() time.Time
	// dial is dialPeer, replaceable in tests
	dial  func(ctx context.Context, addr string) (*peer, error)
	peers func(ctx context.Context) []string

	mu          sync.Mutex
	chain       *headerChain
	syncedAt    time.Time
	lastAttempt time.Time
	syncing     sync.Mutex
}

func newHeaderSync(file string, logf func(string, ...any)) (*headerSync, error) {
	s := &headerSync{file: file, logf: logf, now: time.Now, dial: dialPeer, peers: seedPeers}
	first, headers, err := decodeWindow(builtinCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("built-in checkpoint: %w", err)
	}
	chain, err := newHeaderChain(first, headers)
	if err != nil {
		return nil, fmt.Errorf("built-in checkpoint: %w", err)
	}
	s.chain = chain
	if saved := s.loadSaved(chain); saved != nil {
		s.chain = saved
	}
	tip := s.chain.tip()
	logf("headers: starting from block %d (%s old)", tip.height, s.age(tip).Round(time.Minute))
	return s, nil
}

// loadSaved: the window saved by the last sync, if it is newer than the
// built-in checkpoint and agrees with it
func (s *headerSync) loadSaved(builtin *headerChain) *headerChain {
	data, err := os.ReadFile(s.file)
	if err != nil {
		return nil
	}
	first, headers, err := decodeWindow(data)
	if err != nil {
		return nil
	}
	saved, err := newHeaderChain(first, headers)
	if err != nil || saved.tip().height <= builtin.tip().height {
		return nil
	}
	if e := saved.at(builtin.tip().height); e != nil && e.hash != builtin.tip().hash {
		s.logf("headers: the saved chain differs from the built-in checkpoint, ignoring it")
		return nil
	}
	return saved
}

func (s *headerSync) age(e *chainEntry) time.Duration {
	return s.now().Sub(time.Unix(int64(e.header.Time), 0))
}

func (s *headerSync) run(ctx context.Context) {
	for {
		err := s.sync(ctx)
		wait := syncEvery
		if err != nil {
			s.logf("headers: %v", err)
			wait = syncRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// sync brings the window up to date from up to two peers that answer
func (s *headerSync) sync(ctx context.Context) error {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	s.mu.Lock()
	s.lastAttempt = s.now()
	// Work on a copy: lookups read s.chain meanwhile
	chain := s.chain.clone()
	s.mu.Unlock()

	addrs := s.peers(ctx)
	if len(addrs) == 0 {
		return errors.New("no peers: the DNS seeds did not answer")
	}
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })

	// Many nodes never answer getheaders (pruned or still syncing): ask
	// several at once and keep the first two that do
	answers, lastErr := s.firstAnswers(ctx, addrs, chain.locator(), 2)
	if len(answers) == 0 {
		return fmt.Errorf("no peer sent headers (%v)", lastErr)
	}
	answered := 0
	for _, a := range answers {
		next, added, err := s.syncFrom(ctx, a, chain)
		a.peer.close()
		if err != nil {
			lastErr = err
			continue
		}
		answered++
		if added > 0 {
			chain = next
		}
	}
	if answered == 0 {
		return fmt.Errorf("no usable headers (%v)", lastErr)
	}

	tip := chain.tip()
	s.mu.Lock()
	grew := tip.height != s.chain.tip().height
	s.chain = chain
	if s.age(tip) < maxTipAge {
		s.syncedAt = s.now()
	}
	s.mu.Unlock()
	if grew {
		if err := os.WriteFile(s.file+".tmp", encodeWindow(chain.entries), 0o600); err == nil {
			os.Rename(s.file+".tmp", s.file)
		}
		s.logf("headers: synced to block %d (%s old), %d peer(s)", tip.height, s.age(tip).Round(time.Minute), answered)
	}
	if s.age(tip) >= maxTipAge {
		return fmt.Errorf("newest block %d is %s old: peers are behind", tip.height, s.age(tip).Round(time.Minute))
	}
	return nil
}

type peerAnswer struct {
	peer    *peer
	headers []*header // its answer to the first getheaders
}

// firstAnswers connects to up to 8 peers at a time and returns the first
// want of them that answer getheaders
func (s *headerSync) firstAnswers(ctx context.Context, addrs []string, locator [][32]byte, want int) ([]*peerAnswer, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan *peerAnswer)
	errs := make(chan error)
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
				p, err := s.dial(ctx, addr)
				if err == nil {
					var hs []*header
					if hs, err = p.getHeaders(locator); err == nil {
						select {
						case results <- &peerAnswer{peer: p, headers: hs}:
							return
						case <-ctx.Done():
						}
					}
					p.close()
				}
				select {
				case errs <- err:
				case <-ctx.Done():
				}
			}()
		}
	}()
	var out []*peerAnswer
	var lastErr error
	for failed := 0; len(out) < want && failed+len(out) < len(addrs); {
		select {
		case a := <-results:
			out = append(out, a)
		case err := <-errs:
			failed++
			lastErr = err
		case <-ctx.Done():
			return out, ctx.Err()
		}
	}
	return out, lastErr
}

// syncFrom continues with one peer until it has no more headers. It returns
// the resulting chain (chain itself, extended, or a fork with more work).
func (s *headerSync) syncFrom(ctx context.Context, a *peerAnswer, chain *headerChain) (*headerChain, int, error) {
	p, addr := a.peer, a.peer.addr
	added := 0
	first := true
	for ctx.Err() == nil {
		headers := a.headers
		// The first answer came for an older locator: if another peer
		// already gave us those headers, ask again from our tip
		stale := first && len(headers) > 0 && chain.has(headers[len(headers)-1].hash())
		if !first || stale {
			var err error
			if headers, err = p.getHeaders(chain.locator()); err != nil {
				return chain, added, err
			}
		}
		first = false
		if len(headers) == 0 {
			break
		}
		if headers[0].PrevBlock != chain.tip().hash {
			// The peer is on another branch from an older locator hash
			fork, err := chain.forkAt(headers[0].PrevBlock)
			if err != nil {
				return chain, added, fmt.Errorf("%s: %w", addr, err)
			}
			for _, h := range headers {
				if err := fork.connect(h, s.now()); err != nil {
					return chain, added, fmt.Errorf("%s: %w", addr, err)
				}
			}
			if fork.tip().work.Cmp(chain.tip().work) <= 0 {
				return chain, added, nil // less work: keep ours
			}
			s.logf("headers: %s is on a branch with more work, switching to it", addr)
			chain, added = fork, added+len(headers)
		} else {
			for _, h := range headers {
				if err := chain.connect(h, s.now()); err != nil {
					return chain, added, fmt.Errorf("%s: %w", addr, err)
				}
				added++
			}
		}
		if len(headers) < maxHeadersPerMessage {
			break
		}
	}
	return chain, added, nil
}

// checkRoot: is root a tree root of the verified chain, recent enough for a
// proof? Returns how it was checked, for the log.
func (s *headerSync) checkRoot(ctx context.Context, root []byte) (string, error) {
	desc, err := s.lookupRoot(root)
	if errors.Is(err, errUnknownRoot) {
		// A root newer than our tip: sync now, at most once a minute
		s.mu.Lock()
		due := s.now().Sub(s.lastAttempt) >= resyncMinGap
		s.mu.Unlock()
		if due && s.sync(ctx) == nil {
			desc, err = s.lookupRoot(root)
		}
	}
	return desc, err
}

func (s *headerSync) lookupRoot(root []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syncedAt.IsZero() || s.age(s.chain.tip()) >= maxTipAge {
		return "", errHeadersNotSynced
	}
	var key [32]byte
	copy(key[:], root)
	e, ok := s.chain.roots[key]
	if !ok {
		return "", errUnknownRoot
	}
	age := s.age(e)
	if age > maxProofRootAge {
		return "", fmt.Errorf("tree root from block %d is %s old, too old for a proof", e.height, age.Round(time.Hour))
	}
	return fmt.Sprintf("root %x… is block %d's, %s old, checked against %d synced headers",
		root[:6], e.height, age.Round(time.Hour), len(s.chain.entries)), nil
}

func (c *headerChain) has(hash [32]byte) bool {
	for i := len(c.entries) - 1; i >= 0; i-- {
		if c.entries[i].hash == hash {
			return true
		}
	}
	return false
}

func (c *headerChain) clone() *headerChain {
	out := &headerChain{entries: append([]*chainEntry{}, c.entries...), roots: make(map[[32]byte]*chainEntry, len(c.roots))}
	for k, v := range c.roots {
		out.roots[k] = v
	}
	return out
}

// forkAt: a copy of the chain cut back to the block with this hash, for
// connecting another branch
func (c *headerChain) forkAt(hash [32]byte) (*headerChain, error) {
	for i := len(c.entries) - 1; i >= 0; i-- {
		if c.entries[i].hash != hash {
			continue
		}
		if i+1 < minWindow {
			return nil, errors.New("fork too deep for the window")
		}
		fork := &headerChain{roots: map[[32]byte]*chainEntry{}}
		for _, e := range c.entries[:i+1] {
			fork.add(e)
		}
		return fork, nil
	}
	return nil, errors.New("headers from an unknown branch")
}
