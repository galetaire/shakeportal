// fingertipd: Fingertip's DANE proxy for Handshake names, run by the Android
// app as a child process (shipped in the APK as libfingertipd.so).
//
// The app's own proxy (LocalProxy.kt, the one the VPN hands to every app)
// sends ICANN names straight out and forwards only Handshake names here. This
// proxy, built on letsdane (github.com/buffrr/letsdane, Apache-2.0, as Dit and
// Fingertip use), checks each site's certificate against its TLSA record and
// re-signs the connection with a local CA that the user installs once.
//
//   - Handshake names are resolved by Fingertip itself (resolver.go): the
//     top-level name's on-chain record comes from the Stateless DANE proof
//     services (onchain.go), its nameservers are asked directly, and every
//     answer is checked from the on-chain DS. No Handshake resolver is
//     trusted. The proofs' tree roots are checked against block headers
//     this program syncs from Handshake peers and verifies (headersync.go),
//     starting from a checkpoint built into it (checkpoint.go).
//   - CA: created on first start in <data>/ca. Its name constraints exclude
//     every ICANN top-level domain and the special-use names, so even a
//     stolen key cannot sign certificates for gmail.com or a bank.
//   - Its own ICANN lookups (proof services, nameservers) go to the DNS servers the app
//     passes in (-dns): a Linux binary on Android has no /etc/resolv.conf.
//   - Listens on the loopback only, and exits when the app closes its stdin,
//     so it never outlives the app.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buffrr/letsdane"
)

// Names that are never Handshake names: special-use names (RFC 6761 and
// friends) besides the ICANN list. The CA may not sign them.
var specialUse = []string{"local", "localhost", "onion", "test", "invalid", "example", "internal", "alt", "home.arpa"}

const (
	caName     = "Fingertip DANE (phone)"
	caValidity = 5 * 365 * 24 * time.Hour
)

// IANA's tlds-alpha-by-domain.txt: a "#" header line, then one TLD per line
func loadTLDs(file string) (map[string]struct{}, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tlds := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tlds[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// A truncated list must not produce a CA that can sign ICANN names
	if len(tlds) < 1000 {
		return nil, fmt.Errorf("only %d TLDs in %s, expected over 1000", len(tlds), file)
	}
	for _, name := range specialUse {
		tlds[name] = struct{}{}
	}
	return tlds, nil
}

// ---------- CA ----------

type authority struct {
	cert *x509.Certificate
	key  interface{}
}

func writeFile(file string, data []byte, mode os.FileMode) error {
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

func loadOrCreateCA(dir string, constraints map[string]struct{}) (*authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")

	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	switch {
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		log.Printf("creating a new CA")
		cert, key, err := letsdane.NewAuthority(caName, "Fingertip", caValidity, constraints)
		if err != nil {
			return nil, fmt.Errorf("could not create the CA: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		// Key first: a certificate without its key would block the next start
		if err := writeFile(keyFile, keyPEM, 0o600); err != nil {
			return nil, err
		}
		if err := writeFile(certFile, certPEM, 0o644); err != nil {
			return nil, err
		}
	case certErr != nil || keyErr != nil:
		return nil, fmt.Errorf("%s and %s must both exist or both be missing", certFile, keyFile)
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load the CA: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: pair.PrivateKey}, nil
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.Join(parts, ":")
}

// ---------- DNS for this process's own lookups ----------

// useDNSServers makes every Go lookup (the DoH server's name) go to these
// servers ("ip:port", tried in order) instead of /etc/resolv.conf.
func useDNSServers(servers []string) {
	if len(servers) == 0 {
		return
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			var lastErr error
			for _, server := range servers {
				conn, err := d.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func parseServers(list string) []string {
	var out []string
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(strings.Trim(s, "[]"), "53")
		}
		out = append(out, s)
	}
	return out
}

// ---------- main ----------

func main() {
	log.SetFlags(0)
	listen := flag.String("listen", "127.0.0.1:8081", "address to listen on (loopback)")
	dataDir := flag.String("data", ".", "directory for the CA")
	tldFile := flag.String("tlds", "icann-tlds.txt", "IANA's TLD list")
	dnsList := flag.String("dns", "", "comma-separated DNS servers for this process's own lookups")
	services := flag.String("services", strings.Join(defaultServices, ","), "comma-separated Stateless DANE proof services")
	verbose := flag.Bool("v", false, "log every connection")
	makeCP := flag.String("make-checkpoint", "", "build time: write a fresh checkpoint to this file and exit")
	flag.Parse()
	if *makeCP != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		if err := makeCheckpoint(ctx, *makeCP); err != nil {
			log.Fatalf("checkpoint: %v", err)
		}
		return
	}
	letsdane.Version = "0.6.1 (Fingertip)"

	// The app holds our stdin open: when it closes (the app stopped us or
	// died), exit instead of lingering
	go func() {
		io.Copy(io.Discard, os.Stdin)
		log.Printf("app gone, exiting")
		os.Exit(0)
	}()

	useDNSServers(parseServers(*dnsList))

	direct, err := loadTLDs(*tldFile)
	if err != nil {
		log.Fatalf("could not load the ICANN TLD list: %v", err)
	}
	ca, err := loadOrCreateCA(filepath.Join(*dataDir, "ca"), direct)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("CA SHA-256 %s", fingerprint(ca.cert))

	isICANN := func(name string) bool {
		_, ok := direct[tldOf(name)]
		return ok
	}
	var serviceList []string
	for _, s := range strings.Split(*services, ",") {
		if s = strings.TrimRight(strings.TrimSpace(s), "/"); s != "" {
			serviceList = append(serviceList, s)
		}
	}
	headers, err := newHeaderSync(filepath.Join(*dataDir, "headers.bin"), log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	go headers.run(context.Background())

	chain := newOnChain(serviceList, &http.Client{Timeout: 15 * time.Second})
	chain.checkRoot = headers.checkRoot
	resolver := newHNSResolver(chain, isICANN)
	resolver.logf = log.Printf

	proxyConfig := &letsdane.Config{
		Certificate: ca.cert,
		PrivateKey:  ca.key,
		Validity:    time.Hour,
		Resolver:    resolver,
		// ICANN names never come here (the app sends them direct), but if one
		// does it is tunnelled as it is, without TLSA lookups
		Constraints:    direct,
		SkipNameChecks: false,
		Verbose:        *verbose,
	}
	handler, err := proxyConfig.NewHandler()
	if err != nil {
		log.Fatal(err)
	}

	host, _, err := net.SplitHostPort(*listen)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		log.Fatalf("-listen must be a loopback address, got %q", *listen)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("could not listen on %s: %v", *listen, err)
	}
	log.Printf("listening on %s, on-chain records from %s", *listen, strings.Join(serviceList, ", "))

	// No write timeout: CONNECT tunnels stay open as long as the browser needs
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	log.Fatal(server.Serve(listener))
}
