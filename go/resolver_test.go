package main

import (
	"context"
	"crypto"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---------- a small signed Handshake TLD, served from memory ----------
//
// testtld.            signed, DS on chain, nameserver 10.0.0.1 (glue)
//   _443._tcp.testtld. TLSA, testtld. A
//   sub.testtld.      delegated with a DS, own key, nameserver 10.0.0.2
//   plain.testtld.    delegated without DS (unsigned), nameserver 10.0.0.3

type testZone struct {
	name  string
	key   *dns.DNSKEY
	priv  crypto.Signer
	data  map[rrsetKey][]dns.RR
	sigs  map[rrsetKey][]dns.RR
	cuts  map[string][]dns.RR // child zone -> NS, DS, RRSIG(DS)
	glue  map[string][]dns.RR
	unsig bool
}

func newTestZone(t *testing.T, name string, unsigned bool) *testZone {
	t.Helper()
	z := &testZone{name: name, data: map[rrsetKey][]dns.RR{}, sigs: map[rrsetKey][]dns.RR{}, cuts: map[string][]dns.RR{}, glue: map[string][]dns.RR{}, unsig: unsigned}
	z.key = &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := z.key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	z.priv = priv.(crypto.Signer)
	if !unsigned {
		z.add(t, z.key)
	}
	return z
}

func (z *testZone) sign(t *testing.T, set []dns.RR) *dns.RRSIG {
	t.Helper()
	owner := set[0].Header().Name
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: set[0].Header().Rrtype,
		Algorithm:   z.key.Algorithm,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     set[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      z.key.KeyTag(),
		SignerName:  z.name,
	}
	if err := sig.Sign(z.priv, set); err != nil {
		t.Fatal(err)
	}
	return sig
}

func rr(t *testing.T, text string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (z *testZone) add(t *testing.T, records ...dns.RR) {
	t.Helper()
	k := rrsetKey{strings.ToLower(records[0].Header().Name), records[0].Header().Rrtype}
	z.data[k] = append(z.data[k], records...)
	if !z.unsig {
		z.sigs[k] = []dns.RR{z.sign(t, z.data[k])}
	}
}

// delegate child to a nameserver at ip; with a DS when childKey is set
func (z *testZone) delegate(t *testing.T, child, ip string, childKey *dns.DNSKEY) {
	t.Helper()
	ns := "ns." + child
	z.cuts[child] = []dns.RR{rr(t, child+" 3600 IN NS "+ns)}
	if childKey != nil {
		ds := childKey.ToDS(dns.SHA256)
		ds.Hdr.Ttl = 3600
		z.cuts[child] = append(z.cuts[child], ds, z.sign(t, []dns.RR{ds}))
	}
	z.glue[child] = []dns.RR{rr(t, ns+" 3600 IN A "+ip)}
}

func (z *testZone) answer(q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(&dns.Msg{Question: []dns.Question{q}})
	m.Authoritative = true
	qname := strings.ToLower(q.Name)
	for child, cut := range z.cuts {
		if dns.IsSubDomain(child, qname) {
			m.Authoritative = false
			m.Ns = append(m.Ns, cut...)
			m.Extra = append(m.Extra, z.glue[child]...)
			return m
		}
	}
	k := rrsetKey{qname, q.Qtype}
	if set, ok := z.data[k]; ok {
		m.Answer = append(append(m.Answer, set...), z.sigs[k]...)
		return m
	}
	for key := range z.data {
		if key.name == qname {
			return m // the name exists, no records of this type
		}
	}
	m.Rcode = dns.RcodeNameError
	return m
}

type testWorld struct {
	tld, sub, plain *testZone
	resolver        *hnsResolver
}

func newTestWorld(t *testing.T) *testWorld {
	t.Helper()
	w := &testWorld{
		tld:   newTestZone(t, "testtld.", false),
		sub:   newTestZone(t, "sub.testtld.", false),
		plain: newTestZone(t, "plain.testtld.", true),
	}
	w.tld.add(t, rr(t, "testtld. 3600 IN A 192.0.2.1"))
	w.tld.add(t, rr(t, "_443._tcp.testtld. 3600 IN TLSA 3 1 1 aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"))
	w.tld.delegate(t, "sub.testtld.", "10.0.0.2", w.sub.key)
	w.tld.delegate(t, "plain.testtld.", "10.0.0.3", nil)
	w.sub.add(t, rr(t, "_443._tcp.sub.testtld. 3600 IN TLSA 3 1 1 1111111111111111111111111111111111111111111111111111111111111111"))
	w.plain.add(t, rr(t, "_443._tcp.plain.testtld. 3600 IN TLSA 3 1 1 2222222222222222222222222222222222222222222222222222222222222222"))

	chain := newOnChain(nil, nil)
	w.resolver = newHNSResolver(chain, func(name string) bool { return tldOf(name) == "com" })
	w.resolver.exchange = func(_ context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
		zone := map[string]*testZone{"10.0.0.1:53": w.tld, "10.0.0.2:53": w.sub, "10.0.0.3:53": w.plain}[server]
		if zone == nil {
			return nil, errors.New("unreachable")
		}
		return zone.answer(m.Question[0]), nil
	}
	w.setChainDS(t, w.tld.key.ToDS(dns.SHA256).Digest)
	return w
}

// setChainDS puts testtld's on-chain record in the cache, with this DS digest
// ("" for none)
func (w *testWorld) setChainDS(t *testing.T, digest string) {
	t.Helper()
	res := &hnsResource{Glue: []hnsGlue{{Name: "ns.testtld.", IP: net.ParseIP("10.0.0.1")}}}
	if digest != "" {
		raw, err := hex.DecodeString(digest)
		if err != nil {
			t.Fatal(err)
		}
		res.DS = []hnsDS{{KeyTag: w.tld.key.KeyTag(), Algorithm: w.tld.key.Algorithm, DigestType: dns.SHA256, Digest: raw}}
	}
	w.resolver.chain.cache["testtld"] = &tldRecord{TLD: "testtld", Exists: true, Resource: res, How: "test", fetched: time.Now()}
	w.resolver.keys = map[string]keyEntry{}
	w.resolver.answers = map[rrsetKey]*answer{}
}

func lookupTLSA(t *testing.T, r *hnsResolver, name string) ([]*dns.TLSA, bool, error) {
	t.Helper()
	return r.LookupTLSA(context.Background(), "443", "tcp", name)
}

func TestResolverProvesTLSA(t *testing.T) {
	w := newTestWorld(t)
	for name, want := range map[string]bool{"testtld": true, "sub.testtld": true, "plain.testtld": false} {
		tlsa, secure, err := lookupTLSA(t, w.resolver, name)
		if err != nil || len(tlsa) != 1 || secure != want {
			t.Errorf("%s: %d TLSA, secure %v (want %v), err %v", name, len(tlsa), secure, want, err)
		}
	}
	ips, _, err := w.resolver.LookupIP(context.Background(), "ip4", "testtld")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("address of testtld: %v, %v", ips, err)
	}
	tlsa, secure, err := lookupTLSA(t, w.resolver, "missing.testtld")
	if err != nil || len(tlsa) != 0 || secure {
		t.Errorf("missing name: %v %v %v", tlsa, secure, err)
	}
}

func TestResolverRefusesTamperedAnswer(t *testing.T) {
	w := newTestWorld(t)
	k := rrsetKey{"_443._tcp.testtld.", dns.TypeTLSA}
	w.tld.data[k][0].(*dns.TLSA).Certificate = strings.Repeat("ab", 32) // after signing
	if _, secure, err := lookupTLSA(t, w.resolver, "testtld"); err == nil || secure {
		t.Errorf("a changed TLSA record must be refused, got secure %v err %v", secure, err)
	}
	// Stripping the signature must not turn it into an "insecure" answer
	w = newTestWorld(t)
	delete(w.tld.sigs, k)
	if _, _, err := lookupTLSA(t, w.resolver, "testtld"); err == nil {
		t.Error("an unsigned answer in a signed zone must be refused")
	}
}

func TestResolverNeedsTheOnChainDS(t *testing.T) {
	w := newTestWorld(t)
	w.setChainDS(t, strings.Repeat("00", 32))
	if _, _, err := lookupTLSA(t, w.resolver, "testtld"); err == nil {
		t.Error("keys that do not match the on-chain DS must be refused")
	}
	// Another DS for sub.testtld in the parent: the child's keys do not match
	w = newTestWorld(t)
	other := newTestZone(t, "sub.testtld.", false)
	w.tld.delegate(t, "sub.testtld.", "10.0.0.2", other.key)
	if _, _, err := lookupTLSA(t, w.resolver, "sub.testtld"); err == nil {
		t.Error("a child zone whose keys do not match its DS must be refused")
	}
	// No DS on chain: the TLD is unsigned, answers are insecure
	w = newTestWorld(t)
	w.setChainDS(t, "")
	if tlsa, secure, err := lookupTLSA(t, w.resolver, "testtld"); err != nil || secure || len(tlsa) != 1 {
		t.Errorf("unsigned TLD: %d TLSA, secure %v, err %v", len(tlsa), secure, err)
	}
}

// ---------- on-chain record ----------

func TestAgree(t *testing.T) {
	services := []string{"https://a.example", "https://b.example"}
	root := make([]byte, 32)
	other := make([]byte, 32)
	other[0] = 1
	value := []byte{3, 'f', 'o', 'o', 0, 0}

	rec, err := agree("foo", services, []*provenRecord{{services[0], root, value}, {services[1], root, value}}, []error{nil, nil})
	if err != nil || !rec.Exists || !strings.Contains(rec.How, "agreed by 2") {
		t.Errorf("agreeing services: %+v %v", rec, err)
	}
	if _, err := agree("foo", services, []*provenRecord{{services[0], root, value}, {services[1], other, value}}, []error{nil, nil}); err == nil {
		t.Error("different roots must be refused")
	}
	if _, err := agree("foo", services, []*provenRecord{{services[0], root, value}, {services[1], root, []byte{3, 'f', 'o', 'o', 0, 1}}}, []error{nil, nil}); err == nil {
		t.Error("different records must be refused")
	}
	rec, err = agree("foo", services, []*provenRecord{nil, {services[1], root, value}}, []error{errors.New("down"), nil})
	if err != nil || !strings.Contains(rec.How, "b.example only") {
		t.Errorf("one service: %+v %v", rec, err)
	}
	rec, err = agree("foo", services, []*provenRecord{{services[0], root, nil}, {services[1], root, nil}}, []error{nil, nil})
	if err != nil || rec.Exists {
		t.Errorf("a proof of absence: %+v %v", rec, err)
	}
	if _, err := agree("foo", services, []*provenRecord{nil, nil}, []error{errors.New("x"), errors.New("y")}); err == nil {
		t.Error("no answer must be an error")
	}
}

func TestParseResource(t *testing.T) {
	name := func(n string) []byte {
		buf := make([]byte, 256)
		off, err := dns.PackDomainName(n, buf, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:off]
	}
	var res []byte
	res = append(res, 0) // version
	res = append(res, 1) // NS
	res = append(res, name("ns1.varo.domains.")...)
	res = append(res, 2) // GLUE4
	res = append(res, name("ns1.foo.")...)
	res = append(res, 192, 0, 2, 53)
	res = append(res, 4, 198, 51, 100, 7)                        // SYNTH4
	res = append(res, 0, 0x30, 0x39, 13, 2, 3, 0xaa, 0xbb, 0xcc) // DS 12345 alg 13 SHA-256
	res = append(res, 6, 1, 2, 'h', 'i')                         // TXT
	got, err := parseResource(res)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NS) != 1 || got.NS[0] != "ns1.varo.domains." {
		t.Errorf("NS %v", got.NS)
	}
	if len(got.Glue) != 1 || got.Glue[0].Name != "ns1.foo." || !got.Glue[0].IP.Equal(net.ParseIP("192.0.2.53")) {
		t.Errorf("glue %v", got.Glue)
	}
	if len(got.Synth) != 1 || !got.Synth[0].Equal(net.ParseIP("198.51.100.7")) {
		t.Errorf("synth %v", got.Synth)
	}
	if len(got.DS) != 1 || got.DS[0].KeyTag != 12345 || got.DS[0].Algorithm != 13 || hex.EncodeToString(got.DS[0].Digest) != "aabbcc" {
		t.Errorf("DS %+v", got.DS)
	}
}

func TestSynthIP(t *testing.T) {
	enc := strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte{192, 0, 2, 1}))
	if ip := synthIP("_" + enc + "._synth."); !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("synthIP = %v", ip)
	}
	if synthIP("ns1.example.") != nil {
		t.Error("a normal name is not synthetic")
	}
}

// ---------- live, against the real chain and nameservers ----------

// Needs the network: run with FINGERTIP_LIVE=1 (build-go.ps1 -Live)
func TestResolverLive(t *testing.T) {
	if os.Getenv("FINGERTIP_LIVE") != "1" {
		t.Skip("set FINGERTIP_LIVE=1 to resolve real Handshake names")
	}
	r := newHNSResolver(newOnChain(defaultServices, &http.Client{Timeout: 15 * time.Second}), func(name string) bool {
		switch tldOf(name) {
		case "com", "net", "org", "io", "au", "work", "domains", "dev", "app", "xyz":
			return true
		}
		return false
	})
	r.logf = t.Logf
	for _, name := range []string{"belikebill", "just.belikebill", "nathan.woodburn", "hnsdoh"} {
		ips, _, err := r.LookupIP(context.Background(), "ip", name)
		if err != nil || len(ips) == 0 {
			t.Errorf("%s: no address: %v", name, err)
			continue
		}
		tlsa, secure, err := lookupTLSA(t, r, name)
		if err != nil || len(tlsa) == 0 || !secure {
			t.Errorf("%s: %d TLSA, secure %v, err %v", name, len(tlsa), secure, err)
		}
		t.Logf("%s: %v, %d TLSA, secure %v", name, ips, len(tlsa), secure)
	}
}
