package main

// A window of verified Handshake block headers, as an SPV client keeps
// them. It starts from a trusted run of headers (the checkpoint built into
// the app, or the window saved by the last sync) and accepts a new header
// only when it checks out exactly as hsd checks it (lib/blockchain/chain.js
// v8.0.0, MIT License): it links to the tip, its proof of work meets its
// target, its target is the one hsd's retargeting gives, and its time is
// after the median of the last 11 and not too far in the future.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// Mainnet proof-of-work parameters (lib/protocol/networks.js)
var (
	powLimit, _   = new(big.Int).SetString("0000000000ffff00000000000000000000000000000000000000000000000000", 16)
	powBits       = uint32(0x1c00ffff)
	targetSpacing = uint64(10 * 60)
	blocksPerDay  = uint32(144)
	minActual     = uint64(blocksPerDay/4) * targetSpacing
	maxActual     = uint64(blocksPerDay*4) * targetSpacing
)

const (
	medianTimespan = 11
	// Retargeting looks 144 blocks back, then at two more: a window must
	// hold this many headers before the next one can be checked
	minWindow = int(144 + 3)
	// Headers kept: a bit over two weeks (proofs use roots up to ~15 days old)
	keepHeaders    = 3000
	maxFutureDrift = 2 * time.Hour
)

type chainEntry struct {
	header *header
	hash   [32]byte
	height uint32
	work   *big.Int // chain work since the start of the window
}

type headerChain struct {
	entries []*chainEntry // contiguous, oldest first
	roots   map[[32]byte]*chainEntry
}

var errNotConnected = errors.New("header does not connect to the tip")

// newHeaderChain trusts a run of headers that start at height first.
// They must link to each other, but their targets are not checked: that is
// what makes them the trusted start.
func newHeaderChain(first uint32, headers []*header) (*headerChain, error) {
	if len(headers) < minWindow {
		return nil, fmt.Errorf("a starting window needs %d headers, got %d", minWindow, len(headers))
	}
	c := &headerChain{roots: map[[32]byte]*chainEntry{}}
	work := new(big.Int)
	for i, h := range headers {
		e := &chainEntry{header: h, hash: h.hash(), height: first + uint32(i)}
		if i > 0 && h.PrevBlock != c.entries[i-1].hash {
			return nil, fmt.Errorf("starting window breaks at height %d", e.height)
		}
		if !verifyPOW(e.hash, h.Bits) {
			return nil, fmt.Errorf("starting window: no valid proof of work at height %d", e.height)
		}
		work = new(big.Int).Add(work, proofOf(h.Bits))
		e.work = work
		c.add(e)
	}
	return c, nil
}

func (c *headerChain) add(e *chainEntry) {
	c.entries = append(c.entries, e)
	if _, seen := c.roots[e.header.TreeRoot]; !seen {
		c.roots[e.header.TreeRoot] = e
	}
	if len(c.entries) > keepHeaders {
		drop := c.entries[0]
		c.entries = c.entries[1:]
		if c.roots[drop.header.TreeRoot] == drop {
			delete(c.roots, drop.header.TreeRoot)
			// The same root in a later header (roots last 36 blocks)
			for _, later := range c.entries {
				if later.header.TreeRoot == drop.header.TreeRoot {
					c.roots[later.header.TreeRoot] = later
					break
				}
			}
		}
	}
}

func (c *headerChain) tip() *chainEntry { return c.entries[len(c.entries)-1] }

// at returns the entry at height, or nil if outside the window
func (c *headerChain) at(height uint32) *chainEntry {
	first := c.entries[0].height
	if height < first || height > c.tip().height {
		return nil
	}
	return c.entries[height-first]
}

// suitable: the median-time block of prev and its two predecessors
func (c *headerChain) suitable(prev *chainEntry) (*chainEntry, error) {
	z, y, x := prev, c.at(prev.height-1), c.at(prev.height-2)
	if y == nil || x == nil {
		return nil, errors.New("window too short to retarget")
	}
	if x.header.Time > z.header.Time {
		x, z = z, x
	}
	if x.header.Time > y.header.Time {
		x, y = y, x
	}
	if y.header.Time > z.header.Time {
		y, z = z, y
	}
	return y, nil
}

// target: the bits the block after prev must have (chain.js getTarget)
func (c *headerChain) target(prev *chainEntry) (uint32, error) {
	if prev.height < blocksPerDay+2 {
		return powBits, nil
	}
	last, err := c.suitable(prev)
	if err != nil {
		return 0, err
	}
	ancestor := c.at(prev.height - blocksPerDay)
	if ancestor == nil {
		return 0, errors.New("window too short to retarget")
	}
	first, err := c.suitable(ancestor)
	if err != nil {
		return 0, err
	}
	return retarget(first, last), nil
}

// retarget: chain.js retarget
func retarget(first, last *chainEntry) uint32 {
	work := new(big.Int).Sub(last.work, first.work)
	work.Mul(work, new(big.Int).SetUint64(targetSpacing))
	actual := int64(last.header.Time) - int64(first.header.Time)
	actual = max(actual, int64(minActual))
	actual = min(actual, int64(maxActual))
	work.Div(work, big.NewInt(actual))
	if work.Sign() == 0 {
		return powBits
	}
	target := new(big.Int).Div(maxChainwork, work)
	target.Sub(target, big.NewInt(1))
	if target.Cmp(powLimit) > 0 {
		return powBits
	}
	return toCompact(target)
}

// medianTime: the median time of prev and the 10 blocks before it
func (c *headerChain) medianTime(prev *chainEntry) uint64 {
	var times []uint64
	for e := prev; e != nil && len(times) < medianTimespan; e = c.at(e.height - 1) {
		times = append(times, e.header.Time)
		if e.height == 0 {
			break
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	return times[len(times)/2]
}

// connect checks h as the next block and adds it
func (c *headerChain) connect(h *header, now time.Time) error {
	prev := c.tip()
	if h.PrevBlock != prev.hash {
		return errNotConnected
	}
	height := prev.height + 1
	hash := h.hash()
	if !verifyPOW(hash, h.Bits) {
		return fmt.Errorf("block %d: proof of work does not meet its target", height)
	}
	bits, err := c.target(prev)
	if err != nil {
		return err
	}
	if h.Bits != bits {
		return fmt.Errorf("block %d: target %08x, expected %08x", height, h.Bits, bits)
	}
	if h.Time <= c.medianTime(prev) {
		return fmt.Errorf("block %d: time is before the median of the last 11 blocks", height)
	}
	if time.Unix(int64(h.Time), 0).After(now.Add(maxFutureDrift)) {
		return fmt.Errorf("block %d: time is more than 2 hours ahead", height)
	}
	c.add(&chainEntry{header: h, hash: hash, height: height, work: new(big.Int).Add(prev.work, proofOf(h.Bits))})
	return nil
}

// locator: hashes for getheaders, newest first (tip, then back in steps)
func (c *headerChain) locator() [][32]byte {
	var out [][32]byte
	step := uint32(1)
	for height := c.tip().height; ; {
		e := c.at(height)
		if e == nil {
			break
		}
		out = append(out, e.hash)
		if len(out) >= 10 {
			step *= 2
		}
		if height < c.entries[0].height+step {
			break
		}
		height -= step
	}
	if first := c.entries[0].hash; out[len(out)-1] != first {
		out = append(out, first)
	}
	return out
}

// ---------- storage: start height, then raw headers ----------

func encodeWindow(entries []*chainEntry) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, entries[0].height)
	for _, e := range entries {
		b.Write(e.header.encode())
	}
	return b.Bytes()
}

func decodeWindow(data []byte) (uint32, []*header, error) {
	if len(data) < 4 || (len(data)-4)%headerSize != 0 {
		return 0, nil, errors.New("not a header window")
	}
	first := binary.LittleEndian.Uint32(data)
	var out []*header
	for off := 4; off < len(data); off += headerSize {
		h, err := decodeHeader(data[off : off+headerSize])
		if err != nil {
			return 0, nil, err
		}
		out = append(out, h)
	}
	return first, out, nil
}

func hashHex(h [32]byte) string { return hex.EncodeToString(h[:]) }
