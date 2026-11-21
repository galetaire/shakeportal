package main

// Per-site results for the app. Every decision about a Handshake site is
// printed as one line the app turns into its site list:
//
//	@site <name> <status> <detail>
//
// A line is printed only when a site's result changes, since a browser
// opens many connections per site. letsdane's own refusals (the served
// certificate does not match the proven TLSA record) are picked out of its
// log and reported the same way.

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

const (
	siteVerifiedSANE      = "verified-sane"      // proofs from its own certificate
	siteVerified          = "verified"           // DNSSEC from the on-chain DS
	siteVerifiedUnchecked = "verified-unchecked" // same, root not checked yet
	siteNotDANE           = "not-dane"           // no TLSA record: not re-signed
	siteUnsigned          = "unsigned"           // TLSA without DNSSEC: not used
	siteRefused           = "refused"            // DNSSEC or certificate check failed
	siteFailed            = "failed"             // not found or unreachable
)

// A DNSSEC check that failed (as opposed to a network problem)
type bogusError struct{ err error }

func (e *bogusError) Error() string { return e.err.Error() }
func (e *bogusError) Unwrap() error { return e.err }

func asBogus(err error) error {
	if err == nil || isBogus(err) {
		return err
	}
	return &bogusError{err}
}

func isBogus(err error) bool {
	var b *bogusError
	return errors.As(err, &b)
}

type siteReporter struct {
	out  io.Writer
	mu   sync.Mutex
	last map[string]string
}

func newSiteReporter(out io.Writer) *siteReporter {
	return &siteReporter{out: out, last: map[string]string{}}
}

func (s *siteReporter) report(site, status, detail string) {
	detail = strings.Join(strings.Fields(detail), " ")
	line := fmt.Sprintf("@site %s %s %s\n", site, status, detail)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last[site] == status+" "+detail {
		return
	}
	s.last[site] = status + " " + detail
	io.WriteString(s.out, line)
}

// letsdane: "[WARN] tunnel: 502 CONNECT name:443 dial remote host failed: ..."
var letsdaneWarn = regexp.MustCompile(`\[WARN\] tunnel: \d+ CONNECT (\S+):\d+ (.*)$`)

// logFilter passes the log through and reports letsdane's refusals
type logFilter struct {
	out      io.Writer
	reporter *siteReporter
}

func (f *logFilter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		m := letsdaneWarn.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		site := strings.ToLower(strings.TrimSuffix(m[1], "."))
		switch {
		case strings.Contains(m[2], "dane authentication failed"):
			f.reporter.report(site, siteRefused, "its certificate does not match its proven TLSA record")
		case strings.Contains(m[2], "dial remote host failed"):
			f.reporter.report(site, siteFailed, "the site did not answer: "+m[2])
		}
	}
	return f.out.Write(p)
}
