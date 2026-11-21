package main

// Just enough of Handshake's peer protocol (hsd lib/net, v8.0.0) to ask a
// full node for block headers: version/verack, getheaders/headers, ping/pong.
// Plain TCP on port 12038, which hsd nodes accept besides brontide. A peer
// is not trusted: every header it sends is checked (headerchain.go).

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	mainnetMagic = 1533997779
	mainnetPort  = 12038
	maxMessage   = 8 * 1000 * 1000

	msgVersion    = 0
	msgVerack     = 1
	msgPing       = 2
	msgPong       = 3
	msgGetHeaders = 10
	msgHeaders    = 11

	maxHeadersPerMessage = 2000
)

var dnsSeeds = []string{"hs-mainnet.bcoin.ninja", "seed.htools.work"}

type peer struct {
	conn net.Conn
	r    *bufio.Reader
	addr string
}

func dialPeer(ctx context.Context, addr string) (*peer, error) {
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	p := &peer{conn: conn, r: bufio.NewReader(conn), addr: addr}
	if err := p.handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake with %s: %w", addr, err)
	}
	return p, nil
}

func (p *peer) close() { p.conn.Close() }

func (p *peer) send(cmd byte, payload []byte) error {
	msg := make([]byte, 9+len(payload))
	binary.LittleEndian.PutUint32(msg[0:], mainnetMagic)
	msg[4] = cmd
	binary.LittleEndian.PutUint32(msg[5:], uint32(len(payload)))
	copy(msg[9:], payload)
	p.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := p.conn.Write(msg)
	return err
}

func (p *peer) receive(deadline time.Time) (byte, []byte, error) {
	p.conn.SetReadDeadline(deadline)
	head := make([]byte, 9)
	if _, err := io.ReadFull(p.r, head); err != nil {
		return 0, nil, err
	}
	if binary.LittleEndian.Uint32(head) != mainnetMagic {
		return 0, nil, errors.New("wrong network magic")
	}
	size := binary.LittleEndian.Uint32(head[5:])
	if size > maxMessage {
		return 0, nil, errors.New("message too large")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(p.r, payload); err != nil {
		return 0, nil, err
	}
	return head[4], payload, nil
}

// versionPayload: hsd VersionPacket.write. No services offered, no relay.
func versionPayload() []byte {
	agent := "/fingertip:0.2.0/"
	b := make([]byte, 0, 128)
	b = binary.LittleEndian.AppendUint32(b, 3) // protocol version
	b = binary.LittleEndian.AppendUint32(b, 0) // services
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint64(b, uint64(time.Now().Unix()))
	b = append(b, make([]byte, 88)...) // remote address: unknown, all zero
	nonce := make([]byte, 8)
	rand.Read(nonce)
	b = append(b, nonce...)
	b = append(b, byte(len(agent)))
	b = append(b, agent...)
	b = binary.LittleEndian.AppendUint32(b, 0) // our height
	b = append(b, 1)                           // no relay
	return b
}

func (p *peer) handshake() error {
	if err := p.send(msgVersion, versionPayload()); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	gotVersion, gotVerack := false, false
	for !gotVersion || !gotVerack {
		cmd, payload, err := p.receive(deadline)
		if err != nil {
			return err
		}
		switch cmd {
		case msgVersion:
			gotVersion = true
			if err := p.send(msgVerack, nil); err != nil {
				return err
			}
		case msgVerack:
			gotVerack = true
		case msgPing:
			p.send(msgPong, payload)
		}
	}
	return nil
}

func appendVarint(b []byte, n uint64) []byte {
	switch {
	case n < 0xfd:
		return append(b, byte(n))
	case n <= 0xffff:
		return binary.LittleEndian.AppendUint16(append(b, 0xfd), uint16(n))
	case n <= 0xffffffff:
		return binary.LittleEndian.AppendUint32(append(b, 0xfe), uint32(n))
	}
	return binary.LittleEndian.AppendUint64(append(b, 0xff), n)
}

func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errShort
	}
	switch b[0] {
	case 0xfd:
		if len(b) < 3 {
			return 0, 0, errShort
		}
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3, nil
	case 0xfe:
		if len(b) < 5 {
			return 0, 0, errShort
		}
		return uint64(binary.LittleEndian.Uint32(b[1:])), 5, nil
	case 0xff:
		if len(b) < 9 {
			return 0, 0, errShort
		}
		return binary.LittleEndian.Uint64(b[1:]), 9, nil
	}
	return uint64(b[0]), 1, nil
}

// getHeaders asks for the headers after the first locator hash the peer
// knows (up to 2000). Pruned or still-syncing hsd nodes never answer, so a
// silent peer times out.
func (p *peer) getHeaders(locator [][32]byte) ([]*header, error) {
	payload := appendVarint(nil, uint64(len(locator)))
	for _, h := range locator {
		payload = append(payload, h[:]...)
	}
	payload = append(payload, make([]byte, 32)...) // stop: none
	if err := p.send(msgGetHeaders, payload); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		cmd, payload, err := p.receive(deadline)
		if err != nil {
			return nil, err
		}
		switch cmd {
		case msgPing:
			p.send(msgPong, payload)
		case msgHeaders:
			count, off, err := readVarint(payload)
			if err != nil {
				return nil, err
			}
			if count > maxHeadersPerMessage || uint64(len(payload)-off) != count*headerSize {
				return nil, errors.New("malformed headers message")
			}
			out := make([]*header, 0, count)
			for i := uint64(0); i < count; i++ {
				h, err := decodeHeader(payload[off : off+headerSize])
				if err != nil {
					return nil, err
				}
				out = append(out, h)
				off += headerSize
			}
			return out, nil
		}
	}
}

// seedPeers: peer addresses from the DNS seeds, through the phone's DNS
func seedPeers(ctx context.Context) []string {
	var out []string
	seen := map[string]bool{}
	for _, seed := range dnsSeeds {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", seed)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			addr := net.JoinHostPort(ip.String(), fmt.Sprint(mainnetPort))
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out
}
