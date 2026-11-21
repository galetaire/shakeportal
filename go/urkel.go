package main

// Urkel tree proofs, as used by Handshake for its name tree. Copied from
// Dit (galetaire/dit, docker/dane/urkel.go, 21 Nov 2026).
//
// A Go port of the proof decoding and verification in urkel's lib/proof.js,
// lib/common.js and lib/bits.js (https://github.com/handshake-org/urkel,
// v1.0.3), MIT License, Copyright (c) 2018 Christopher Jeffrey. Only what a
// verifier needs: decode a proof and check it against a tree root.
//
// Handshake's tree uses BLAKE2b-256 and 256-bit keys (the SHA3-256 of a name).
// Integers in the encoding are little-endian.

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

const (
	urkelBits     = 256
	urkelHashSize = 32

	proofDeadend   = 0
	proofShort     = 1
	proofCollision = 2
	proofExists    = 3
)

var proofTypeNames = []string{"deadend", "short", "collision", "exists"}

// A bit string: the first size bits of data, most significant bit first
type bitString struct {
	size int
	data []byte
}

func bitAt(data []byte, index int) int {
	return int(data[index>>3]>>(7-uint(index&7))) & 1
}

// has: does this prefix match key starting at bit depth?
func (b bitString) has(key []byte, depth int) bool {
	length := b.size
	if rest := len(key)*8 - depth; rest < length {
		length = rest
	}
	n := 0
	for i := 0; i < length; i++ {
		if bitAt(b.data, i) != bitAt(key, depth+i) {
			break
		}
		n++
	}
	return n == b.size
}

type proofNode struct {
	prefix bitString
	hash   []byte
}

type urkelProof struct {
	kind   int
	depth  int
	nodes  []proofNode
	prefix bitString // short
	left   []byte    // short
	right  []byte    // short
	key    []byte    // collision
	hash   []byte    // collision
	value  []byte    // exists
}

type reader struct {
	data []byte
	pos  int
}

var errShort = errors.New("proof data ends too early")

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, errShort
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *reader) u16le() (int, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return int(b[0]) | int(b[1])<<8, nil
}

// bits.js read: 1 byte size, or 2 bytes when the high bit is set, then the bits
func (r *reader) bits() (bitString, error) {
	b, err := r.take(1)
	if err != nil {
		return bitString{}, err
	}
	size := int(b[0])
	if size&0x80 != 0 {
		b2, err := r.take(1)
		if err != nil {
			return bitString{}, err
		}
		size = (size-0x80)*0x100 + int(b2[0])
	}
	data, err := r.take((size + 7) >> 3)
	if err != nil {
		return bitString{}, err
	}
	return bitString{size: size, data: data}, nil
}

// decodeUrkelProof reads one proof at the reader's position (proof.js read)
func decodeUrkelProof(r *reader) (*urkelProof, error) {

	field, err := r.u16le()
	if err != nil {
		return nil, err
	}
	p := &urkelProof{kind: field >> 14, depth: field &^ (3 << 14)}
	if p.depth > urkelBits {
		return nil, errors.New("invalid proof depth")
	}
	count, err := r.u16le()
	if err != nil {
		return nil, err
	}
	if count > urkelBits {
		return nil, errors.New("proof too large")
	}
	// One bit per node: does it carry a prefix?
	bitfield, err := r.take((count + 7) >> 3)
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		var prefix bitString
		if bitAt(bitfield, i) == 1 {
			if prefix, err = r.bits(); err != nil {
				return nil, err
			}
			if prefix.size == 0 || prefix.size > urkelBits {
				return nil, errors.New("invalid prefix size")
			}
		}
		hash, err := r.take(urkelHashSize)
		if err != nil {
			return nil, err
		}
		p.nodes = append(p.nodes, proofNode{prefix: prefix, hash: hash})
	}
	switch p.kind {
	case proofDeadend:
	case proofShort:
		if p.prefix, err = r.bits(); err != nil {
			return nil, err
		}
		if p.prefix.size == 0 || p.prefix.size > urkelBits {
			return nil, errors.New("invalid prefix size")
		}
		if p.left, err = r.take(urkelHashSize); err != nil {
			return nil, err
		}
		if p.right, err = r.take(urkelHashSize); err != nil {
			return nil, err
		}
	case proofCollision:
		if p.key, err = r.take(urkelBits / 8); err != nil {
			return nil, err
		}
		if p.hash, err = r.take(urkelHashSize); err != nil {
			return nil, err
		}
	case proofExists:
		size, err := r.u16le()
		if err != nil {
			return nil, err
		}
		if p.value, err = r.take(size); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid proof type")
	}
	return p, nil
}

func blake(parts ...[]byte) []byte {
	h, _ := blake2b.New256(nil)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

// common.js hashInternal: plain or with a skipped prefix
func hashInternal(prefix bitString, left, right []byte) []byte {
	if prefix.size == 0 {
		return blake([]byte{0x01}, left, right)
	}
	size := []byte{byte(prefix.size), byte(prefix.size >> 8)}
	return blake([]byte{0x02}, size, prefix.data, left, right)
}

func hashLeaf(key, valueHash []byte) []byte {
	return blake([]byte{0x00}, key, valueHash)
}

// verify recomputes the root from the proof for key (proof.js verify).
// It returns the proven value for an "exists" proof, nil for proofs that
// the key is absent.
func (p *urkelProof) verify(root, key []byte) ([]byte, error) {
	if len(root) != urkelHashSize || len(key) != urkelBits/8 {
		return nil, errors.New("bad root or key size")
	}
	if len(p.nodes) > urkelBits {
		return nil, errors.New("proof not sane")
	}

	var leaf []byte
	switch p.kind {
	case proofDeadend:
		leaf = make([]byte, urkelHashSize)
	case proofShort:
		if p.prefix.has(key, p.depth) {
			return nil, errors.New("proof: same path")
		}
		leaf = hashInternal(p.prefix, p.left, p.right)
	case proofCollision:
		if bytes.Equal(p.key, key) {
			return nil, errors.New("proof: same key")
		}
		leaf = hashLeaf(p.key, p.hash)
	case proofExists:
		if len(p.value) > 0xffff {
			return nil, errors.New("proof not sane")
		}
		leaf = hashLeaf(key, blake(p.value))
	default:
		return nil, errors.New("proof not sane")
	}

	next := leaf
	depth := p.depth
	// Walk up the tree, bits right to left
	for i := len(p.nodes) - 1; i >= 0; i-- {
		node := p.nodes[i]
		if depth < node.prefix.size+1 {
			return nil, errors.New("proof: negative depth")
		}
		depth--
		if bitAt(key, depth) == 1 {
			next = hashInternal(node.prefix, node.hash, next)
		} else {
			next = hashInternal(node.prefix, next, node.hash)
		}
		depth -= node.prefix.size
		if !node.prefix.has(key, depth) {
			return nil, errors.New("proof: path mismatch")
		}
	}
	if depth != 0 {
		return nil, errors.New("proof: too deep")
	}
	if !bytes.Equal(next, root) {
		return nil, errors.New("proof does not lead to this tree root")
	}
	return p.value, nil
}

// A HIP-17 Urkel blob: 1 byte count, then per proof a 32-byte tree root and
// the proof (format used by htools-org/stateless-dane and randomlogin/sane)
type rootedProof struct {
	root  []byte
	proof *urkelProof
}

func decodeUrkelBlob(blob []byte) ([]rootedProof, error) {
	if len(blob) < 1 {
		return nil, errors.New("empty Urkel data")
	}
	count := int(blob[0])
	if count == 0 {
		return nil, errors.New("no proofs in the Urkel data")
	}
	r := &reader{data: blob, pos: 1}
	var out []rootedProof
	for i := 0; i < count; i++ {
		root, err := r.take(urkelHashSize)
		if err != nil {
			return nil, fmt.Errorf("proof %d: %w", i+1, err)
		}
		p, err := decodeUrkelProof(r)
		if err != nil {
			return nil, fmt.Errorf("proof %d: %w", i+1, err)
		}
		out = append(out, rootedProof{root: root, proof: p})
	}
	return out, nil
}
