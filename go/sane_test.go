package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// belikebill's certificate as Castell 0.4.0 served it on 21 Nov 2026, with
// both HIP-17 extensions (testdata/belikebill.crt, from Dit)
func loadCert(t *testing.T, file string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A resolver whose roots are the built-in checkpoint's, at its time
func saneResolver(t *testing.T) *hnsResolver {
	t.Helper()
	s := testSync(t)
	chain := newOnChain(nil, nil)
	chain.checkRoot = s.checkRoot
	r := newHNSResolver(chain, func(name string) bool { return tldOf(name) == "com" })
	r.now = s.now
	r.exchange = func(context.Context, *dns.Msg, string) (*dns.Msg, error) {
		t.Fatal("no nameserver may be asked")
		return nil, nil
	}
	return r
}

func TestBelikebillProvesItselfFromItsCertificate(t *testing.T) {
	cert := loadCert(t, "testdata/belikebill.crt")
	urkel, chain := proofExtensions(cert)
	if urkel == nil || chain == nil {
		t.Fatal("expected both HIP-17 extensions")
	}
	r := saneResolver(t)
	tlsa, how, err := r.verifyCertProofs(context.Background(), "belikebill", urkel, chain)
	if err != nil {
		t.Fatalf("proofs do not verify: %v", err)
	}
	if !strings.Contains(how, "checked against") {
		t.Errorf("root not checked against the headers: %s", how)
	}
	// The key step letsdane does: the served certificate matches the TLSA
	if len(tlsa) == 0 || tlsa[0].Verify(cert) != nil {
		t.Fatalf("the proven TLSA %v does not match the certificate", tlsa)
	}
	t.Logf("%d TLSA proven, %s", len(tlsa), how)

	// The same proofs in a certificate with another key: the proofs still
	// verify, but the proven TLSA does not match that key, so letsdane
	// refuses the site
	fake := certWithProofs(t, cert)
	if tlsa[0].Verify(fake) == nil {
		t.Error("the proven TLSA must not match a certificate with another key")
	}

	// A changed byte in the DNSSEC chain breaks it
	broken := append([]byte{}, chain...)
	at := bytes.Index(broken, tlsaDigest(t, tlsa[0]))
	if at < 0 {
		t.Fatal("TLSA digest not found in the chain")
	}
	broken[at] ^= 1
	if _, _, err := r.verifyCertProofs(context.Background(), "belikebill", urkel, broken); err == nil {
		t.Error("a changed TLSA in the chain must be refused")
	}
	// The proofs belong to belikebill only
	if _, _, err := r.verifyCertProofs(context.Background(), "other", urkel, chain); err == nil {
		t.Error("belikebill's proofs must not prove another name")
	}
}

func TestLookupTLSAUsesTheCertificateFirst(t *testing.T) {
	cert := loadCert(t, "testdata/belikebill.crt")
	r := saneResolver(t)
	var reports []string
	r.report = func(site, status, detail string) { reports = append(reports, site+" "+status) }
	// Its address is known (cached), and the "site" serves the certificate
	hdr := dns.RR_Header{Name: "belikebill.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
	r.store(rrsetKey{"belikebill.", dns.TypeA}, &answer{records: []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.10")}}}, time.Hour)
	r.store(rrsetKey{"belikebill.", dns.TypeAAAA}, &answer{}, time.Hour)
	old := fetchCert
	fetchCert = func(context.Context, string, []net.IP) (*x509.Certificate, error) { return cert, nil }
	t.Cleanup(func() { fetchCert = old })

	tlsa, secure, err := r.LookupTLSA(context.Background(), "443", "tcp", "belikebill")
	if err != nil || !secure || len(tlsa) == 0 {
		t.Fatalf("%d TLSA, secure %v, err %v", len(tlsa), secure, err)
	}
	if len(reports) != 1 || reports[0] != "belikebill verified-sane" {
		t.Errorf("reports %v", reports)
	}
}

func certWithProofs(t *testing.T, real *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "belikebill"},
		DNSNames:     []string{"belikebill"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	for _, ext := range real.Extensions {
		if ext.Id.Equal(oidUrkelProof) || ext.Id.Equal(oidDNSSECChain) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	fake, _ := x509.ParseCertificate(der)
	return fake
}

func tlsaDigest(t *testing.T, r *dns.TLSA) []byte {
	t.Helper()
	b := make([]byte, len(r.Certificate)/2)
	for i := range b {
		var v byte
		for _, c := range r.Certificate[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c|0x20-'a') + 10
			}
		}
		b[i] = v
	}
	return b
}

func TestSiteReportsAndLetsdaneRefusals(t *testing.T) {
	var out bytes.Buffer
	rep := newSiteReporter(&out)
	rep.report("belikebill", siteVerified, "TLSA  proven")
	rep.report("belikebill", siteVerified, "TLSA proven") // same: not repeated
	f := &logFilter{out: &bytes.Buffer{}, reporter: rep}
	f.Write([]byte("[WARN] tunnel: 502 CONNECT belikebill:443 dial remote host failed: tls: dane authentication failed\n"))
	want := "@site belikebill verified TLSA proven\n@site belikebill refused its certificate does not match its proven TLSA record\n"
	if out.String() != want {
		t.Errorf("got %q", out.String())
	}
}
