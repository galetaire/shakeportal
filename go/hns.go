package main

// Handshake name data, as proven by an Urkel proof: the key is the SHA3-256
// of the top-level name, the value is the name's on-chain state, which holds
// its DNS resource (hsd lib/covenants/namestate.js, lib/dns/resource.js,
// MIT License). Based on Dit's hns.go (galetaire/dit, docker/dane), extended
// here to read the nameservers too, since this app resolves Handshake names
// itself from the on-chain data.

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func nameKey(tld string) []byte {
	sum := sha3.Sum256([]byte(strings.ToLower(tld)))
	return sum[:]
}

type nameState struct {
	name     string
	resource []byte
}

// NameState.read: name (1-byte length), data (2-byte little-endian length), ...
func decodeNameState(value []byte) (*nameState, error) {
	r := &reader{data: value}
	n, err := r.take(1)
	if err != nil {
		return nil, err
	}
	name, err := r.take(int(n[0]))
	if err != nil {
		return nil, err
	}
	size, err := r.u16le()
	if err != nil {
		return nil, err
	}
	data, err := r.take(size)
	if err != nil {
		return nil, err
	}
	return &nameState{name: string(name), resource: data}, nil
}

// A DS record from a Handshake resource
type hnsDS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// A nameserver with its address on chain (GLUE4/GLUE6)
type hnsGlue struct {
	Name string
	IP   net.IP
}

// What the resolver needs from a name's on-chain resource
type hnsResource struct {
	DS    []hnsDS
	NS    []string  // nameserver names (fully qualified)
	Glue  []hnsGlue // nameservers with their addresses
	Synth []net.IP  // SYNTH4/SYNTH6: nameserver addresses without a name
}

// readName reads a DNS name at the reader's position. Names in a resource
// may use compression pointers, relative to the start of the resource.
func (r *reader) readName() (string, error) {
	name, next, err := dns.UnpackDomainName(r.data, r.pos)
	if err != nil {
		return "", fmt.Errorf("bad name in resource: %w", err)
	}
	r.pos = next
	return strings.ToLower(dns.Fqdn(name)), nil
}

// parseResource decodes a resource (Resource.read). Records: 0 DS, 1 NS,
// 2 GLUE4, 3 GLUE6, 4 SYNTH4, 5 SYNTH6, 6 TXT; decoding stops at an unknown
// type, as hsd does.
func parseResource(resource []byte) (*hnsResource, error) {
	out := &hnsResource{}
	if len(resource) == 0 {
		return out, nil
	}
	r := &reader{data: resource}
	version, _ := r.take(1)
	if version[0] != 0 {
		return nil, fmt.Errorf("unknown resource version %d", version[0])
	}
	for r.pos < len(r.data) {
		t, _ := r.take(1)
		switch t[0] {
		case 0: // DS
			head, err := r.take(4)
			if err != nil {
				return nil, err
			}
			n, err := r.take(1)
			if err != nil {
				return nil, err
			}
			digest, err := r.take(int(n[0]))
			if err != nil {
				return nil, err
			}
			out.DS = append(out.DS, hnsDS{
				KeyTag:     uint16(head[0])<<8 | uint16(head[1]),
				Algorithm:  head[2],
				DigestType: head[3],
				Digest:     digest,
			})
		case 1: // NS
			name, err := r.readName()
			if err != nil {
				return nil, err
			}
			out.NS = append(out.NS, name)
		case 2, 3: // GLUE4, GLUE6
			name, err := r.readName()
			if err != nil {
				return nil, err
			}
			size := 4
			if t[0] == 3 {
				size = 16
			}
			ip, err := r.take(size)
			if err != nil {
				return nil, err
			}
			out.Glue = append(out.Glue, hnsGlue{Name: name, IP: append(net.IP{}, ip...)})
		case 4, 5: // SYNTH4, SYNTH6
			size := 4
			if t[0] == 5 {
				size = 16
			}
			ip, err := r.take(size)
			if err != nil {
				return nil, err
			}
			out.Synth = append(out.Synth, append(net.IP{}, ip...))
		case 6: // TXT: count, then length-prefixed strings
			c, err := r.take(1)
			if err != nil {
				return nil, err
			}
			for i := 0; i < int(c[0]); i++ {
				l, err := r.take(1)
				if err != nil {
					return nil, err
				}
				if _, err := r.take(int(l[0])); err != nil {
					return nil, err
				}
			}
		default:
			return out, nil
		}
	}
	return out, nil
}

// dsRecords: the on-chain DS records as DNS records of zone
func (res *hnsResource) dsRecords(zone string) []*dns.DS {
	var out []*dns.DS
	for _, d := range res.DS {
		out = append(out, &dns.DS{
			Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     d.KeyTag,
			Algorithm:  d.Algorithm,
			DigestType: d.DigestType,
			Digest:     fmt.Sprintf("%X", d.Digest),
		})
	}
	return out
}

var errNoNameservers = errors.New("no nameservers on chain")
