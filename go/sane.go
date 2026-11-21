package main

// Stateless DANE (HIP-17) from the site itself: a site like those Castell
// serves carries two certificate extensions with its proofs, the Urkel proof
// of its top-level name and the DNSSEC chain down to its TLSA record. When
// they are there, the TLSA record is proven offline:
//
//  1. the Urkel proof must lead to a tree root of the verified header chain
//     (headersync.go), at most 15 days old;
//  2. the DNSSEC chain must verify from the DS records that proof shows on
//     chain (dnssecchain.go).
//
// No nameserver is asked for the TLSA record. The certificate itself is not
// trusted: the proven TLSA goes back to letsdane, which then checks the
// certificate the site serves against it (the "key" step: proofs replayed
// on another server fail there).
//
// Sites without the extensions, or whose proofs do not verify, are checked
// the usual way (resolver.go). The extension IDs are the ones
// htools-org/stateless-dane, randomlogin/sane and Castell use (HIP-17 still
// lists them as "TBD").

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	oidUrkelProof  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54392, 5, 1620}
	oidDNSSECChain = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54392, 5, 1621}

	errNoCertProofs = errors.New("the site's certificate carries no proofs")
)

const saneCacheTTL = time.Hour

type saneEntry struct {
	tlsa    []*dns.TLSA
	how     string
	err     error
	expires time.Time
}

// proofExtensions returns the raw extension values (the HIP-17 blobs)
func proofExtensions(cert *x509.Certificate) (urkel, chain []byte) {
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidUrkelProof):
			urkel = ext.Value
		case ext.Id.Equal(oidDNSSECChain):
			chain = ext.Value
		}
	}
	return urkel, chain
}

// fetchCert: the certificate a site serves, not trusted by itself. A
// variable so tests can replace the network.
var fetchCert = func(ctx context.Context, name string, ips []net.IP) (*x509.Certificate, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config:    &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
		if err != nil {
			lastErr = err
			continue
		}
		certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
		conn.Close()
		if len(certs) == 0 {
			return nil, errors.New("the site sent no certificate")
		}
		return certs[0], nil
	}
	return nil, fmt.Errorf("could not reach the site: %v", lastErr)
}

// saneTLSA proves name's TLSA records from its own certificate. It returns
// errNoCertProofs for sites without the extensions.
func (r *hnsResolver) saneTLSA(ctx context.Context, name string) ([]*dns.TLSA, string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	r.mu.Lock()
	if e, ok := r.sane[name]; ok && r.now().Before(e.expires) {
		r.mu.Unlock()
		return e.tlsa, e.how, e.err
	}
	r.mu.Unlock()

	tlsa, how, err := r.proveFromCert(ctx, name)
	if ctx.Err() == nil { // a lookup cut short is not remembered
		r.mu.Lock()
		r.sane[name] = &saneEntry{tlsa: tlsa, how: how, err: err, expires: r.now().Add(saneCacheTTL)}
		r.mu.Unlock()
	}
	return tlsa, how, err
}

func (r *hnsResolver) proveFromCert(ctx context.Context, name string) ([]*dns.TLSA, string, error) {
	if r.chain.checkRoot == nil {
		return nil, "", errNoCertProofs
	}
	ips, _, err := r.LookupIP(ctx, "ip", name)
	if err != nil {
		return nil, "", err
	}
	cert, err := fetchCert(ctx, name, ips)
	if err != nil {
		return nil, "", err
	}
	urkelBlob, chainBlob := proofExtensions(cert)
	if urkelBlob == nil || chainBlob == nil {
		return nil, "", errNoCertProofs
	}
	return r.verifyCertProofs(ctx, name, urkelBlob, chainBlob)
}

// verifyCertProofs: steps 1 and 2 above
func (r *hnsResolver) verifyCertProofs(ctx context.Context, name string, urkelBlob, chainBlob []byte) ([]*dns.TLSA, string, error) {
	tld := tldOf(name)
	proofs, err := decodeUrkelBlob(urkelBlob)
	if err != nil {
		return nil, "", fmt.Errorf("Urkel proof: %w", err)
	}
	var state *nameState
	var how string
	var lastErr error = errors.New("no proof in the certificate")
	for _, p := range proofs {
		desc, err := r.chain.checkRoot(ctx, p.root)
		if err != nil {
			lastErr = err
			continue
		}
		value, err := p.proof.verify(p.root, nameKey(tld))
		if err != nil {
			lastErr = err
			continue
		}
		if value == nil {
			return nil, "", fmt.Errorf("the proof says %s does not exist", tld)
		}
		if state, err = decodeNameState(value); err != nil || state.name != tld {
			return nil, "", fmt.Errorf("the proven value is not the state of %s", tld)
		}
		how = desc
		break
	}
	if state == nil {
		return nil, "", fmt.Errorf("Urkel proof: %v", lastErr)
	}
	res, err := parseResource(state.resource)
	if err != nil {
		return nil, "", err
	}
	chain, err := verifyChain(chainBlob, name, tld, res.DS, r.now())
	if err != nil {
		return nil, "", fmt.Errorf("DNSSEC chain: %w", err)
	}
	return chain.tlsa, how, nil
}
