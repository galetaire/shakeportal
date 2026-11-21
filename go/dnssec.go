package main

// DNSSEC checks shared by the resolver. Copied from Dit's dnssecchain.go
// (galetaire/dit, docker/dane, 21 Nov 2026).

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type rrsetKey struct {
	name  string
	rtype uint16
}

// dsMatches: does key hash to this DS (key tag, algorithm and digest)?
func dsMatches(key *dns.DNSKEY, ds *dns.DS) bool {
	if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
		return false
	}
	computed := key.ToDS(ds.DigestType)
	return computed != nil && strings.EqualFold(computed.Digest, ds.Digest)
}

// verifySet: is set signed, now, by one of keys belonging to signer?
func verifySet(set []dns.RR, sigs []*dns.RRSIG, signer string, keys []*dns.DNSKEY, now time.Time) error {
	if len(set) == 0 {
		return errors.New("empty record set")
	}
	var lastErr error = fmt.Errorf("no signature by %s", signer)
	for _, sig := range sigs {
		if !strings.EqualFold(dns.Fqdn(sig.SignerName), signer) {
			continue
		}
		for _, key := range keys {
			if key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(key, set); err != nil {
				lastErr = fmt.Errorf("signature by %s (key %d) does not verify: %v", signer, key.KeyTag(), err)
				continue
			}
			if !sig.ValidityPeriod(now) {
				lastErr = fmt.Errorf("signature by %s (key %d) is outside its validity period", signer, key.KeyTag())
				continue
			}
			return nil
		}
	}
	return lastErr
}

// splitSets groups records into RRsets and their signatures, by owner+type
func splitSets(records []dns.RR) (map[rrsetKey][]dns.RR, map[rrsetKey][]*dns.RRSIG) {
	sets := map[rrsetKey][]dns.RR{}
	sigs := map[rrsetKey][]*dns.RRSIG{}
	for _, rr := range records {
		owner := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if sig, ok := rr.(*dns.RRSIG); ok {
			k := rrsetKey{owner, sig.TypeCovered}
			sigs[k] = append(sigs[k], sig)
			continue
		}
		k := rrsetKey{owner, rr.Header().Rrtype}
		sets[k] = append(sets[k], rr)
	}
	return sets, sigs
}
