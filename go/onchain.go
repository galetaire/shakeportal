package main

// A top-level name's on-chain record, from the public Stateless DANE proof
// services. A service only hands over an Urkel proof; the proof is checked
// here against the tree root it names, so a service cannot invent or change
// a record for that root.
//
// The root itself must be a tree root of the block headers the app synced
// and checked (headersync.go), at most 15 days old: then a service cannot
// lie at all, it can only fail to answer. Only while the headers are not
// synced yet (the first seconds, or no peer reachable) a root is accepted
// when every service that answers gives the same root and record, and the
// log says it was NOT checked.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var defaultServices = []string{"https://sdaneproofs.htools.work", "https://sdaneproofs.woodburn.au"}

const (
	recordTTL   = time.Hour
	negativeTTL = 10 * time.Minute
)

// tldRecord is what the chain says about a top-level name
type tldRecord struct {
	TLD      string
	Exists   bool
	Resource *hnsResource
	Root     []byte
	How      string // how the root was accepted, for the log
	fetched  time.Time
}

type onChain struct {
	services []string
	client   *http.Client
	now      func() time.Time
	logf     func(format string, a ...any)
	// checkRoot says whether a root is one of the verified chain (nil: none
	// available, as in tests)
	checkRoot func(ctx context.Context, root []byte) (string, error)
	// peerProof gets the record from a Handshake peer (peerproof.go),
	// tried before the proof services (nil: services only)
	peerProof func(ctx context.Context, tld string) (*provenRecord, error)

	mu    sync.Mutex
	cache map[string]*tldRecord
}

func newOnChain(services []string, client *http.Client) *onChain {
	return &onChain{services: services, client: client, now: time.Now, logf: func(string, ...any) {}, cache: map[string]*tldRecord{}}
}

// one service's answer, already checked against its own root
type provenRecord struct {
	service string
	root    []byte
	value   []byte // nil: the proof says the name does not exist
}

func (o *onChain) fetch(ctx context.Context, service, tld string) (*provenRecord, error) {
	u := service + "/proofs/" + url.PathEscape(tld) + "?urkel"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var doc struct {
		Urkel string `json:"urkel"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("unexpected answer: %v", err)
	}
	blob, err := hex.DecodeString(strings.TrimSpace(doc.Urkel))
	if err != nil || len(blob) == 0 {
		return nil, errors.New("no Urkel proof in the answer")
	}
	proofs, err := decodeUrkelBlob(blob)
	if err != nil {
		return nil, err
	}
	// The first proof that leads to the root it names
	var lastErr error
	for _, p := range proofs {
		value, err := p.proof.verify(p.root, nameKey(tld))
		if err != nil {
			lastErr = err
			continue
		}
		return &provenRecord{service: service, root: p.root, value: value}, nil
	}
	return nil, fmt.Errorf("the proof does not verify: %v", lastErr)
}

// lookup returns the on-chain record of tld, from the cache when fresh
func (o *onChain) lookup(ctx context.Context, tld string) (*tldRecord, error) {
	tld = strings.ToLower(strings.TrimSuffix(tld, "."))
	o.mu.Lock()
	if rec, ok := o.cache[tld]; ok {
		ttl := recordTTL
		if !rec.Exists {
			ttl = negativeTTL
		}
		if o.now().Sub(rec.fetched) < ttl {
			o.mu.Unlock()
			return rec, nil
		}
	}
	o.mu.Unlock()

	if rec := o.fromPeer(ctx, tld); rec != nil {
		return o.remember(tld, rec), nil
	}

	answers := make([]*provenRecord, len(o.services))
	errs := make([]error, len(o.services))
	var wg sync.WaitGroup
	for i, service := range o.services {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i], errs[i] = o.fetch(ctx, service, tld)
		}()
	}
	wg.Wait()

	rec, err := o.accept(ctx, tld, answers, errs)
	if err != nil {
		return nil, err
	}
	return o.remember(tld, rec), nil
}

func (o *onChain) remember(tld string, rec *tldRecord) *tldRecord {
	rec.fetched = o.now()
	o.mu.Lock()
	o.cache[tld] = rec
	o.mu.Unlock()
	return rec
}

// fromPeer: the record proven by a Handshake peer for a root of the verified
// chain, or nil (then the proof services are asked)
func (o *onChain) fromPeer(ctx context.Context, tld string) *tldRecord {
	if o.peerProof == nil || o.checkRoot == nil {
		return nil
	}
	a, err := o.peerProof(ctx, tld)
	if err != nil {
		if !errors.Is(err, errHeadersNotSynced) {
			o.logf("%s: no proof from peers (%v), asking the proof services", tld, err)
		}
		return nil
	}
	how, err := o.checkRoot(ctx, a.root)
	if err != nil {
		o.logf("%s: peer proof root not accepted (%v), asking the proof services", tld, err)
		return nil
	}
	rec, err := recordFrom(tld, a, how+", proof from "+a.service)
	if err != nil {
		o.logf("%s: %v", tld, err)
		return nil
	}
	return rec
}

// accept picks the answer whose root the verified chain knows. Without
// synced headers it falls back to agree.
func (o *onChain) accept(ctx context.Context, tld string, answers []*provenRecord, errs []error) (*tldRecord, error) {
	if o.checkRoot == nil {
		return agree(tld, o.services, answers, errs)
	}
	var problems []string
	for i, a := range answers {
		if a == nil {
			problems = append(problems, fmt.Sprintf("%s: %v", hostOf(o.services[i]), errs[i]))
			continue
		}
		how, err := o.checkRoot(ctx, a.root)
		if errors.Is(err, errHeadersNotSynced) {
			rec, err := agree(tld, o.services, answers, errs)
			if rec != nil {
				rec.How += ", NOT checked: block headers not synced yet"
			}
			return rec, err
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", hostOf(a.service), err))
			continue
		}
		return recordFrom(tld, a, how+", proof from "+hostOf(a.service))
	}
	return nil, fmt.Errorf("no proof for %s with a root of the verified chain (%s)", tld, strings.Join(problems, "; "))
}

// agree turns the services' answers into one record: every service that
// answered must give the same root and the same value
func agree(tld string, services []string, answers []*provenRecord, errs []error) (*tldRecord, error) {
	var first *provenRecord
	var problems []string
	answered := 0
	for i, a := range answers {
		if a == nil {
			problems = append(problems, fmt.Sprintf("%s: %v", hostOf(services[i]), errs[i]))
			continue
		}
		answered++
		if first == nil {
			first = a
			continue
		}
		if !bytes.Equal(a.root, first.root) || !bytes.Equal(a.value, first.value) {
			return nil, fmt.Errorf("proof services disagree about %s (%s and %s): refusing it", tld, hostOf(first.service), hostOf(a.service))
		}
	}
	if first == nil {
		return nil, fmt.Errorf("no proof service answered for %s (%s)", tld, strings.Join(problems, "; "))
	}
	how := fmt.Sprintf("root %x… agreed by %d services", first.root[:6], answered)
	if answered == 1 {
		how = fmt.Sprintf("root %x… from %s only (others: %s)", first.root[:6], hostOf(first.service), strings.Join(problems, "; "))
	}
	return recordFrom(tld, first, how)
}

// recordFrom decodes a proven value into the TLD's record
func recordFrom(tld string, a *provenRecord, how string) (*tldRecord, error) {
	rec := &tldRecord{TLD: tld, Root: a.root, How: how}
	if a.value == nil {
		return rec, nil // proven not to exist
	}
	state, err := decodeNameState(a.value)
	if err != nil || state.name != tld {
		return nil, fmt.Errorf("the proven value is not the state of %s", tld)
	}
	res, err := parseResource(state.resource)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", tld, err)
	}
	rec.Exists, rec.Resource = true, res
	return rec, nil
}

func hostOf(service string) string {
	if u, err := url.Parse(service); err == nil && u.Host != "" {
		return u.Host
	}
	return service
}
