package main

// Handshake block headers and their proof of work, ported from hsd v8.0.0
// (lib/primitives/abstractblock.js, lib/protocol/consensus.js, MIT License,
// Copyright (c) 2017-2018 Christopher Jeffrey). Only what a header-only
// client needs: decode a header, hash it, check its work.

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math/big"

	"golang.org/x/crypto/blake2b"
)

const headerSize = 236

type header struct {
	Nonce        uint32
	Time         uint64
	PrevBlock    [32]byte
	TreeRoot     [32]byte
	ExtraNonce   [24]byte
	ReservedRoot [32]byte
	WitnessRoot  [32]byte
	MerkleRoot   [32]byte
	Version      uint32
	Bits         uint32
	Mask         [32]byte
}

// decodeHeader reads hsd's writeHead layout (all integers little-endian)
func decodeHeader(b []byte) (*header, error) {
	if len(b) != headerSize {
		return nil, errors.New("a header is 236 bytes")
	}
	h := &header{}
	h.Nonce = binary.LittleEndian.Uint32(b[0:])
	h.Time = binary.LittleEndian.Uint64(b[4:])
	copy(h.PrevBlock[:], b[12:44])
	copy(h.TreeRoot[:], b[44:76])
	copy(h.ExtraNonce[:], b[76:100])
	copy(h.ReservedRoot[:], b[100:132])
	copy(h.WitnessRoot[:], b[132:164])
	copy(h.MerkleRoot[:], b[164:196])
	h.Version = binary.LittleEndian.Uint32(b[196:])
	h.Bits = binary.LittleEndian.Uint32(b[200:])
	copy(h.Mask[:], b[204:236])
	return h, nil
}

func (h *header) encode() []byte {
	b := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(b[0:], h.Nonce)
	binary.LittleEndian.PutUint64(b[4:], h.Time)
	copy(b[12:44], h.PrevBlock[:])
	copy(b[44:76], h.TreeRoot[:])
	copy(b[76:100], h.ExtraNonce[:])
	copy(b[100:132], h.ReservedRoot[:])
	copy(b[132:164], h.WitnessRoot[:])
	copy(b[164:196], h.MerkleRoot[:])
	binary.LittleEndian.PutUint32(b[196:], h.Version)
	binary.LittleEndian.PutUint32(b[200:], h.Bits)
	copy(b[204:236], h.Mask[:])
	return b
}

func blake256(parts ...[]byte) []byte {
	d, _ := blake2b.New256(nil)
	for _, p := range parts {
		d.Write(p)
	}
	return d.Sum(nil)
}

// padding: prevBlock XOR treeRoot, repeated to size bytes
func (h *header) padding(size int) []byte {
	pad := make([]byte, size)
	for i := range pad {
		pad[i] = h.PrevBlock[i%32] ^ h.TreeRoot[i%32]
	}
	return pad
}

func (h *header) subHead() []byte {
	var b bytes.Buffer
	b.Write(h.ExtraNonce[:])
	b.Write(h.ReservedRoot[:])
	b.Write(h.WitnessRoot[:])
	b.Write(h.MerkleRoot[:])
	binary.Write(&b, binary.LittleEndian, h.Version)
	binary.Write(&b, binary.LittleEndian, h.Bits)
	return b.Bytes() // 128 bytes
}

func (h *header) commitHash() []byte {
	maskHash := blake256(h.PrevBlock[:], h.Mask[:])
	return blake256(blake256(h.subHead()), maskHash)
}

func (h *header) preHead() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, h.Nonce)
	binary.Write(&b, binary.LittleEndian, h.Time)
	b.Write(h.padding(20))
	b.Write(h.PrevBlock[:])
	b.Write(h.TreeRoot[:])
	b.Write(h.commitHash())
	return b.Bytes() // 128 bytes
}

// hash is the block hash: hsd's powHash (share hash XOR mask)
func (h *header) hash() [32]byte {
	data := h.preHead()
	left := blake2b.Sum512(data)
	right := sha3.Sum256(append(append([]byte{}, data...), h.padding(8)...))
	share := blake256(left[:], h.padding(32), right[:])
	var out [32]byte
	for i := range out {
		out[i] = share[i] ^ h.Mask[i]
	}
	return out
}

// ---------- targets ----------

var maxChainwork = new(big.Int).Lsh(big.NewInt(1), 256)

// fromCompact: the target a "bits" value stands for (nil if negative)
func fromCompact(compact uint32) *big.Int {
	if compact == 0 {
		return new(big.Int)
	}
	exponent := compact >> 24
	negative := (compact>>23)&1 == 1
	mantissa := compact & 0x7fffff
	var num *big.Int
	if exponent <= 3 {
		num = big.NewInt(int64(mantissa >> (8 * (3 - exponent))))
	} else {
		num = new(big.Int).Lsh(big.NewInt(int64(mantissa)), uint(8*(exponent-3)))
	}
	if negative {
		num.Neg(num)
	}
	return num
}

// toCompact: the "bits" value of a (non-negative) target
func toCompact(num *big.Int) uint32 {
	if num.Sign() == 0 {
		return 0
	}
	exponent := uint32((num.BitLen() + 7) / 8)
	var mantissa uint32
	if exponent <= 3 {
		mantissa = uint32(num.Uint64()) << (8 * (3 - exponent))
	} else {
		mantissa = uint32(new(big.Int).Rsh(num, uint(8*(exponent-3))).Uint64())
	}
	if mantissa&0x800000 != 0 {
		mantissa >>= 8
		exponent++
	}
	return exponent<<24 | mantissa
}

// verifyPOW: is the hash, as a big-endian number, at most the target?
func verifyPOW(hash [32]byte, bits uint32) bool {
	target := fromCompact(bits)
	if target.Sign() <= 0 || target.BitLen() > 256 {
		return false
	}
	return new(big.Int).SetBytes(hash[:]).Cmp(target) <= 0
}

// proofOf: the work a block with these bits represents, 2^256 / (target+1)
func proofOf(bits uint32) *big.Int {
	target := fromCompact(bits)
	if target.Sign() <= 0 {
		return new(big.Int)
	}
	return new(big.Int).Div(maxChainwork, target.Add(target, big.NewInt(1)))
}
