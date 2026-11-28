package main

// Plain http:// sites in the app's site list. letsdane fetches them for the
// browser (its NonConnect handler), resolving the name with our resolver,
// but asks for no TLSA record, so nothing else reports them. This wrapper
// watches each plain-HTTP request for a Handshake name and reports
// "plain-http" when the site answered, or "failed" with letsdane's reason
// when it could not be reached.

import (
	"bytes"
	"html"
	"net"
	"net/http"
	"strings"
)

const sitePlainHTTP = "plain-http" // loaded over http://: not encrypted, no DANE

const plainHTTPDetail = "loaded over plain HTTP: not encrypted, so DANE does not apply"

func reportPlainHTTP(next http.Handler, isICANN func(string) bool, report func(site, status, detail string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect || req.URL.Scheme != "http" {
			next.ServeHTTP(w, req)
			return
		}
		site := strings.ToLower(strings.TrimSuffix(req.URL.Hostname(), "."))
		if site == "" || net.ParseIP(site) != nil || isICANN(site) {
			next.ServeHTTP(w, req)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, req)
		if reason, failed := rec.proxyError(); failed {
			report(site, siteFailed, "could not load it over plain HTTP: "+reason)
		} else if rec.status != 0 {
			report(site, sitePlainHTTP, plainHTTPDetail)
		}
	})
}

// statusRecorder notes the status and, for a 502, the start of the body,
// to tell letsdane's own error page from a site's answer
type statusRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.status == http.StatusBadGateway && r.body.Len() < 4096 {
		r.body.Write(p)
	}
	return r.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach Flush and Hijack (streaming,
// WebSocket upgrades) on the real writer
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// proxyError reports letsdane's own error page: a 502 whose body is
// "<h1>502 Bad Gateway</h1><p>reason</p><hr>letsdane/v..." (a site's own 502
// is passed through as an answer)
func (r *statusRecorder) proxyError() (string, bool) {
	body := r.body.String()
	if r.status != http.StatusBadGateway || !strings.Contains(body, "<hr>letsdane/v") {
		return "", false
	}
	reason := "the proxy could not fetch it"
	if start := strings.Index(body, "<p>"); start >= 0 {
		if end := strings.Index(body[start:], "</p>"); end >= 0 {
			reason = html.UnescapeString(body[start+3 : start+end])
		}
	}
	return reason, true
}
