package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/buffrr/letsdane"
	"github.com/miekg/dns"
)

// fakeResolver: "site" and "broken" are at the test server's address,
// "missing" does not exist
type fakeResolver struct{ ip net.IP }

func (f fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error) {
	switch strings.TrimSuffix(host, ".") {
	case "site", "broken":
		return []net.IP{f.ip}, true, nil
	}
	return nil, false, fmt.Errorf("no such name on the Handshake chain")
}

func (f fakeResolver) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	return nil, false, nil
}

func TestPlainHTTPReported(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "broken" || strings.HasPrefix(r.Host, "broken:") {
			http.Error(w, "upstream down", http.StatusBadGateway) // the site's own 502
			return
		}
		io.WriteString(w, "hello from a plain HTTP site")
	}))
	defer backend.Close()
	_, port, _ := net.SplitHostPort(backend.Listener.Addr().String())

	cert, key, err := letsdane.NewAuthority("test CA", "test", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	config := &letsdane.Config{Certificate: cert, PrivateKey: key, Validity: time.Hour,
		Resolver: fakeResolver{ip: net.ParseIP("127.0.0.1")}}
	handler, err := config.NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reporter := newSiteReporter(&out)
	isICANN := func(name string) bool { return strings.HasSuffix(name, ".com") }
	proxy := httptest.NewServer(reportPlainHTTP(handler, isICANN, reporter.report))
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	get := func(host string) (int, string) {
		resp, err := client.Get("http://" + host + ":" + port + "/")
		if err != nil {
			t.Fatalf("GET %s: %v", host, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	if code, body := get("site"); code != 200 || !strings.Contains(body, "hello") {
		t.Fatalf("site: %d %q", code, body)
	}
	get("site") // a second load reports nothing new
	get("broken")
	get("missing")

	want := []string{
		"@site site plain-http " + plainHTTPDetail,
		"@site broken plain-http " + plainHTTPDetail, // it answered, with its own 502
		"@site missing failed could not load it over plain HTTP: ",
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d lines:\n%s", len(lines), out.String())
	}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w) {
			t.Errorf("line %d: got %q, want prefix %q", i, lines[i], w)
		}
	}
	if !strings.Contains(lines[2], "no such name") {
		t.Errorf("the failure should say why: %q", lines[2])
	}
}

func TestPlainHTTPIgnoresICANNAndCONNECT(t *testing.T) {
	var out bytes.Buffer
	reporter := newSiteReporter(&out)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	h := reportPlainHTTP(next, func(name string) bool { return name == "example.com" }, reporter.report)

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		httptest.NewRequest(http.MethodGet, "http://10.0.0.1/", nil),
		httptest.NewRequest(http.MethodConnect, "https://site:443", nil),
	} {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if out.Len() != 0 {
		t.Fatalf("reported: %s", out.String())
	}
}
