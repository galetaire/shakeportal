package main

// Fingertip's own Handshake resolver: no Handshake resolver, no hnsd, no
// peers. For a name under the top-level name T:
//
//  1. T's on-chain record comes from the proof services (onchain.go): its DS
//     records (the DNSSEC anchor) and its nameservers (GLUE, SYNTH or NS).
//  2. Those nameservers are asked directly, without recursion, following
//     delegations down to the name.
//  3. Every answer is checked here from the on-chain DS: T's DNSKEY set, each
//     DS of a delegation, then the answer itself. A signed zone whose
//     signatures do not verify is an error (fail closed), never "insecure".
//
// It implements letsdane's resolver interface, so letsdane uses a TLSA
// record only when it is proven this way.
//
// Not proven (they make an answer "insecure", never a forged "secure"):
// denial of existence (NSEC/NSEC3) and delegations without DS. An attacker
// could use them only to make letsdane skip DANE for a site, and then the
// browser sees the site's own certificate, which it does not trust.

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var errNXDomain = errors.New("no such name")

const (
	maxDelegations = 10
	maxDepth       = 4 // CNAMEs and nameserver names looked up on the way
	lookupTimeout  = 20 * time.Second
	maxCacheTTL    = time.Hour
	minCacheTTL    = 30 * time.Second
)

type answer struct {
	records []dns.RR // the records of the asked type, after any CNAME
	secure  bool     // proven from the on-chain DS
	how     string   // how the on-chain record was accepted
	expires time.Time
}

type keyEntry struct {
	keys    []*dns.DNSKEY
	expires time.Time
}

type hnsResolver struct {
	chain   *onChain
	isICANN func(name string) bool
	// Addresses of ICANN names (nameservers like ns1.example.com)
	icannIP  func(ctx context.Context, host string) ([]net.IP, error)
	exchange func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error)
	now      func() time.Time
	logf     func(format string, a ...any)

	mu      sync.Mutex
	keys    map[string]keyEntry
	answers map[rrsetKey]*answer
}

func newHNSResolver(chain *onChain, isICANN func(string) bool) *hnsResolver {
	return &hnsResolver{
		chain:   chain,
		isICANN: isICANN,
		icannIP: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
		exchange: exchangeDNS,
		now:      time.Now,
		logf:     func(string, ...any) {},
		keys:     map[string]keyEntry{},
		answers:  map[rrsetKey]*answer{},
	}
}

// exchangeDNS asks one server over UDP, and again over TCP if truncated
func exchangeDNS(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
	res, _, err := udp.ExchangeContext(ctx, m, server)
	if err == nil && res.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: 6 * time.Second}
		res, _, err = tcp.ExchangeContext(ctx, m, server)
	}
	return res, err
}

func tldOf(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) == 0 {
		return ""
	}
	return strings.ToLower(labels[len(labels)-1])
}

// ---------- letsdane's resolver interface ----------

func (r *hnsResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error) {
	if ip := net.ParseIP(strings.TrimSuffix(host, ".")); ip != nil {
		return []net.IP{ip}, false, nil
	}
	if r.isICANN(host) {
		ips, err := r.icannIP(ctx, host)
		return ips, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	switch network {
	case "ip4":
		qtypes = qtypes[:1]
	case "ip6":
		qtypes = qtypes[1:]
	}
	var ips []net.IP
	secure := true
	var lastErr error
	for _, qtype := range qtypes {
		a, err := r.resolve(ctx, host, qtype, 0)
		if err != nil {
			lastErr = err
			secure = false
			continue
		}
		secure = secure && a.secure
		for _, rr := range a.records {
			switch t := rr.(type) {
			case *dns.A:
				ips = append(ips, t.A)
			case *dns.AAAA:
				ips = append(ips, t.AAAA)
			}
		}
	}
	if len(ips) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("%s has no address", host)
		}
		return nil, false, lastErr
	}
	return ips, secure, nil
}

func (r *hnsResolver) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	if net.ParseIP(strings.TrimSuffix(name, ".")) != nil || r.isICANN(name) {
		return nil, false, nil
	}
	tlsaName, err := dns.TLSAName(dns.Fqdn(name), service, proto)
	if err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	a, err := r.resolve(ctx, tlsaName, dns.TypeTLSA, 0)
	if errors.Is(err, errNXDomain) {
		r.logf("%s: no TLSA record, not a DANE site", name)
		return nil, false, nil
	}
	if err != nil {
		r.logf("%s: REFUSED, %v", name, err)
		return nil, false, err
	}
	var out []*dns.TLSA
	for _, rr := range a.records {
		if t, ok := rr.(*dns.TLSA); ok {
			out = append(out, t)
		}
	}
	switch {
	case len(out) == 0:
		r.logf("%s: no TLSA record, not a DANE site", name)
	case a.secure:
		r.logf("%s: TLSA proven from the on-chain DS (%s)", name, a.how)
	default:
		r.logf("%s: TLSA found but not signed, so not used", name)
	}
	return out, a.secure, nil
}

// ---------- resolution ----------

// resolveAny resolves a name that may be an ICANN name (a CNAME target)
func (r *hnsResolver) resolveAny(ctx context.Context, name string, qtype uint16, depth int) (*answer, error) {
	if !r.isICANN(name) {
		return r.resolve(ctx, name, qtype, depth)
	}
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return &answer{}, nil
	}
	ips, err := r.icannIP(ctx, name)
	if err != nil {
		return nil, err
	}
	a := &answer{how: "ICANN name " + strings.TrimSuffix(name, ".")}
	for _, ip := range ips {
		hdr := dns.RR_Header{Name: dns.Fqdn(name), Class: dns.ClassINET, Ttl: 300}
		if v4 := ip.To4(); v4 != nil && qtype == dns.TypeA {
			hdr.Rrtype = dns.TypeA
			a.records = append(a.records, &dns.A{Hdr: hdr, A: v4})
		} else if v4 == nil && qtype == dns.TypeAAAA {
			hdr.Rrtype = dns.TypeAAAA
			a.records = append(a.records, &dns.AAAA{Hdr: hdr, AAAA: ip})
		}
	}
	return a, nil
}

func (r *hnsResolver) cached(k rrsetKey) *answer {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.answers[k]; ok && r.now().Before(a.expires) {
		return a
	}
	return nil
}

func (r *hnsResolver) store(k rrsetKey, a *answer, ttl time.Duration) {
	ttl = min(max(ttl, minCacheTTL), maxCacheTTL)
	a.expires = r.now().Add(ttl)
	r.mu.Lock()
	r.answers[k] = a
	r.mu.Unlock()
}

func minTTL(set []dns.RR) time.Duration {
	ttl := maxCacheTTL
	for _, rr := range set {
		ttl = min(ttl, time.Duration(rr.Header().Ttl)*time.Second)
	}
	return ttl
}

// resolve looks up qname/qtype, starting at the top-level name's
// nameservers from the chain
func (r *hnsResolver) resolve(ctx context.Context, qname string, qtype uint16, depth int) (*answer, error) {
	qname = strings.ToLower(dns.Fqdn(qname))
	if depth > maxDepth {
		return nil, errors.New("too many CNAMEs or nameserver lookups")
	}
	key := rrsetKey{qname, qtype}
	if a := r.cached(key); a != nil {
		if a.records == nil && !a.secure && a.how == "nxdomain" {
			return nil, errNXDomain
		}
		return a, nil
	}

	tld := tldOf(qname)
	rec, err := r.chain.lookup(ctx, tld)
	if err != nil {
		return nil, err
	}
	if !rec.Exists {
		r.store(key, &answer{how: "nxdomain"}, time.Minute)
		return nil, fmt.Errorf("%s is not on the Handshake chain: %w", tld, errNXDomain)
	}
	zone := dns.Fqdn(tld)
	servers, err := r.chainServers(ctx, rec.Resource, depth)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tld, err)
	}
	ds := rec.Resource.dsRecords(zone)
	secure := len(ds) > 0
	now := r.now()

	for step := 0; step < maxDelegations; step++ {
		var keys []*dns.DNSKEY
		if secure {
			if keys, err = r.zoneKeys(ctx, zone, servers, ds); err != nil {
				return nil, fmt.Errorf("DNSSEC of %s fails: %w", strings.TrimSuffix(zone, "."), err)
			}
		}
		msg, err := r.ask(ctx, servers, qname, qtype)
		if err != nil {
			return nil, err
		}
		sets, sigs := splitSets(msg.Answer)

		// The answer, or a CNAME to follow
		for _, rtype := range []uint16{qtype, dns.TypeCNAME} {
			set := sets[rrsetKey{qname, rtype}]
			if len(set) == 0 || (rtype == dns.TypeCNAME && qtype == dns.TypeCNAME) {
				continue
			}
			setSecure := secure
			if secure {
				signer, signerKeys, ok, err := r.signerKeys(ctx, zone, keys, servers, qname, sigs[rrsetKey{qname, rtype}])
				if err != nil {
					return nil, err
				}
				setSecure = ok
				if ok {
					if err := verifySet(set, sigs[rrsetKey{qname, rtype}], signer, signerKeys, now); err != nil {
						return nil, fmt.Errorf("%s %s: %w", strings.TrimSuffix(qname, "."), dns.TypeToString[rtype], err)
					}
				}
			}
			if rtype == qtype {
				a := &answer{records: set, secure: setSecure, how: rec.How}
				r.store(key, a, minTTL(set))
				return a, nil
			}
			next, err := r.resolveAny(ctx, set[0].(*dns.CNAME).Target, qtype, depth+1)
			if err != nil {
				return nil, err
			}
			return &answer{records: next.records, secure: setSecure && next.secure, how: rec.How}, nil
		}

		// A delegation to a child zone
		if child, nsNames := referral(msg, zone, qname); child != "" {
			authSets, authSigs := splitSets(msg.Ns)
			if secure {
				childDS := authSets[rrsetKey{child, dns.TypeDS}]
				if len(childDS) == 0 {
					// Not proven unsigned (no NSEC check): treated as insecure
					secure = false
				} else {
					if err := verifySet(childDS, authSigs[rrsetKey{child, dns.TypeDS}], zone, keys, now); err != nil {
						return nil, fmt.Errorf("delegation to %s: %w", strings.TrimSuffix(child, "."), err)
					}
					ds = nil
					for _, rr := range childDS {
						ds = append(ds, rr.(*dns.DS))
					}
				}
			}
			if servers, err = r.referralServers(ctx, msg, nsNames, depth); err != nil {
				return nil, fmt.Errorf("delegation to %s: %w", strings.TrimSuffix(child, "."), err)
			}
			zone = child
			continue
		}

		// No such name, or no records of this type (not proven: insecure)
		if msg.Rcode == dns.RcodeNameError {
			r.store(key, &answer{how: "nxdomain"}, time.Minute)
			return nil, errNXDomain
		}
		a := &answer{how: rec.How}
		r.store(key, a, time.Minute)
		return a, nil
	}
	return nil, errors.New("too many delegations")
}

// signerKeys finds the trusted keys of the zone that signed an answer. A
// server that hosts a child zone too may answer from it directly: then the
// child's DS is asked for and checked first. ok is false when that child has
// no DS (an unsigned child zone).
func (r *hnsResolver) signerKeys(ctx context.Context, zone string, keys []*dns.DNSKEY, servers []string, qname string, sigs []*dns.RRSIG) (string, []*dns.DNSKEY, bool, error) {
	signer := zone
	for _, sig := range sigs {
		s := strings.ToLower(dns.Fqdn(sig.SignerName))
		if s != zone && dns.IsSubDomain(zone, s) && dns.IsSubDomain(s, qname) {
			signer = s
		}
	}
	if signer == zone {
		return zone, keys, true, nil
	}
	msg, err := r.ask(ctx, servers, signer, dns.TypeDS)
	if err != nil {
		return "", nil, false, err
	}
	sets, sigsDS := splitSets(msg.Answer)
	childDS := sets[rrsetKey{signer, dns.TypeDS}]
	if len(childDS) == 0 {
		return signer, nil, false, nil
	}
	if err := verifySet(childDS, sigsDS[rrsetKey{signer, dns.TypeDS}], zone, keys, r.now()); err != nil {
		return "", nil, false, fmt.Errorf("DS of %s: %w", strings.TrimSuffix(signer, "."), err)
	}
	var ds []*dns.DS
	for _, rr := range childDS {
		ds = append(ds, rr.(*dns.DS))
	}
	childKeys, err := r.zoneKeys(ctx, signer, servers, ds)
	if err != nil {
		return "", nil, false, fmt.Errorf("DNSSEC of %s fails: %w", strings.TrimSuffix(signer, "."), err)
	}
	return signer, childKeys, true, nil
}

// zoneKeys returns the DNSKEY set of zone, checked against its DS records
func (r *hnsResolver) zoneKeys(ctx context.Context, zone string, servers []string, ds []*dns.DS) ([]*dns.DNSKEY, error) {
	cacheKey := zone + "|" + ds[0].Digest
	r.mu.Lock()
	if e, ok := r.keys[cacheKey]; ok && r.now().Before(e.expires) {
		r.mu.Unlock()
		return e.keys, nil
	}
	r.mu.Unlock()

	msg, err := r.ask(ctx, servers, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	sets, sigs := splitSets(msg.Answer)
	set := sets[rrsetKey{zone, dns.TypeDNSKEY}]
	var all, anchored []*dns.DNSKEY
	for _, rr := range set {
		key := rr.(*dns.DNSKEY)
		all = append(all, key)
		for _, d := range ds {
			if dsMatches(key, d) {
				anchored = append(anchored, key)
				break
			}
		}
	}
	if len(all) == 0 {
		return nil, errors.New("the zone sent no DNSKEY records")
	}
	if len(anchored) == 0 {
		return nil, errors.New("no DNSKEY matches the DS record")
	}
	now := r.now()
	if err := verifySet(set, sigs[rrsetKey{zone, dns.TypeDNSKEY}], zone, anchored, now); err != nil {
		return nil, fmt.Errorf("DNSKEY set: %w", err)
	}
	ttl := minTTL(set)
	for _, sig := range sigs[rrsetKey{zone, dns.TypeDNSKEY}] {
		if left := time.Unix(int64(sig.Expiration), 0).Sub(now); left < ttl {
			ttl = left
		}
	}
	r.mu.Lock()
	r.keys[cacheKey] = keyEntry{keys: all, expires: now.Add(min(max(ttl, minCacheTTL), maxCacheTTL))}
	r.mu.Unlock()
	return all, nil
}

// ask sends a non-recursive DNSSEC query to the zone's servers, in turn
func (r *hnsResolver) ask(ctx context.Context, servers []string, qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	m.SetEdns0(1232, true)
	var lastErr error
	for _, server := range servers {
		if ctx.Err() != nil {
			break
		}
		res, err := r.exchange(ctx, m, server)
		if err != nil {
			lastErr = err
			continue
		}
		if res.Rcode != dns.RcodeSuccess && res.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("%s answered %s", server, dns.RcodeToString[res.Rcode])
			continue
		}
		return res, nil
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, fmt.Errorf("no nameserver answered for %s: %v", strings.TrimSuffix(qname, "."), lastErr)
}

// referral: is msg a delegation from zone to a child zone that encloses
// qname? Returns the child and its nameserver names.
func referral(msg *dns.Msg, zone, qname string) (string, []string) {
	if len(msg.Answer) > 0 {
		return "", nil
	}
	child := ""
	var names []string
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := strings.ToLower(dns.Fqdn(ns.Hdr.Name))
		if owner == zone || !dns.IsSubDomain(zone, owner) || !dns.IsSubDomain(owner, qname) {
			continue
		}
		if child == "" {
			child = owner
		}
		if owner == child {
			names = append(names, strings.ToLower(dns.Fqdn(ns.Ns)))
		}
	}
	return child, names
}

// synthIP decodes hsd's synthetic nameserver names: _<base32hex(ip)>._synth.
func synthIP(name string) net.IP {
	labels := dns.SplitDomainName(name)
	if len(labels) != 2 || labels[1] != "_synth" || !strings.HasPrefix(labels[0], "_") {
		return nil
	}
	raw, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(labels[0][1:]))
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil
	}
	return net.IP(raw)
}

// nsAddresses looks up a nameserver name: ICANN names through the phone's
// DNS, Handshake names with this resolver
func (r *hnsResolver) nsAddresses(ctx context.Context, name string, depth int) []net.IP {
	if ip := synthIP(name); ip != nil {
		return []net.IP{ip}
	}
	if r.isICANN(name) {
		ips, _ := r.icannIP(ctx, strings.TrimSuffix(name, "."))
		return ips
	}
	var ips []net.IP
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		a, err := r.resolve(ctx, name, qtype, depth+1)
		if err != nil {
			continue
		}
		for _, rr := range a.records {
			switch t := rr.(type) {
			case *dns.A:
				ips = append(ips, t.A)
			case *dns.AAAA:
				ips = append(ips, t.AAAA)
			}
		}
	}
	return ips
}

// serverList: "ip:53" for each address, IPv4 first (not every network has
// IPv6), without duplicates
func serverList(ips []net.IP) []string {
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].To4() != nil && ips[j].To4() == nil })
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		s := net.JoinHostPort(ip.String(), "53")
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// chainServers: the top-level name's nameservers, from its on-chain record
func (r *hnsResolver) chainServers(ctx context.Context, res *hnsResource, depth int) ([]string, error) {
	ips := append([]net.IP{}, res.Synth...)
	glued := map[string]bool{}
	for _, g := range res.Glue {
		ips = append(ips, g.IP)
		glued[g.Name] = true
	}
	if len(ips) == 0 {
		for _, ns := range res.NS {
			if !glued[ns] {
				ips = append(ips, r.nsAddresses(ctx, ns, depth)...)
			}
		}
	}
	if len(ips) == 0 {
		return nil, errNoNameservers
	}
	return serverList(ips), nil
}

// referralServers: a child zone's nameservers, from the glue in the
// referral, else looked up by name
func (r *hnsResolver) referralServers(ctx context.Context, msg *dns.Msg, names []string, depth int) ([]string, error) {
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	var ips []net.IP
	for _, rr := range msg.Extra {
		owner := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if !wanted[owner] {
			continue
		}
		switch t := rr.(type) {
		case *dns.A:
			ips = append(ips, t.A)
		case *dns.AAAA:
			ips = append(ips, t.AAAA)
		}
	}
	if len(ips) == 0 {
		for _, n := range names {
			ips = append(ips, r.nsAddresses(ctx, n, depth)...)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("no address for any of its nameservers")
	}
	return serverList(ips), nil
}
