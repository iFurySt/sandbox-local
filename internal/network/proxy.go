package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/iFurySt/sandbox-local/internal/model"
)

type Proxy struct {
	server   *http.Server
	listener net.Listener
	policy   model.NetworkPolicy
	done     chan struct{}
	cleanup  func() error
}

func StartProxy(policy model.NetworkPolicy) (*Proxy, error) {
	return start(policy, "tcp", "127.0.0.1:0", nil)
}

func StartUnixProxy(policy model.NetworkPolicy) (*Proxy, error) {
	dir, err := os.MkdirTemp("", "sandbox-local-proxy-*")
	if err != nil {
		return nil, err
	}
	socketPath := filepath.Join(dir, "proxy.sock")
	cleanup := func() error {
		return os.RemoveAll(dir)
	}
	proxy, err := start(policy, "unix", socketPath, cleanup)
	if err != nil {
		_ = cleanup()
		return nil, err
	}
	return proxy, nil
}

func start(policy model.NetworkPolicy, network string, address string, cleanup func() error) (*Proxy, error) {
	if err := validatePatterns(policy.Allow); err != nil {
		return nil, err
	}
	if err := validatePatterns(policy.Deny); err != nil {
		return nil, err
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	proxy := &Proxy{
		listener: ln,
		policy:   policy,
		done:     make(chan struct{}),
		cleanup:  cleanup,
	}
	proxy.server = &http.Server{
		Handler:           http.HandlerFunc(proxy.handle),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		defer close(proxy.done)
		err := proxy.server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// The proxy reports per-request failures to the client. Startup
			// failures are returned synchronously before this goroutine starts.
		}
	}()
	return proxy, nil
}

func (p *Proxy) Port() int {
	return p.listener.Addr().(*net.TCPAddr).Port
}

func (p *Proxy) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", p.Port())
}

func (p *Proxy) SocketPath() string {
	if p.listener.Addr().Network() != "unix" {
		return ""
	}
	return p.listener.Addr().String()
}

func (p *Proxy) Close(ctx context.Context) error {
	err := p.server.Shutdown(ctx)
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
	}
	if p.cleanup != nil {
		if cleanupErr := p.cleanup(); err == nil {
			err = cleanupErr
		}
	}
	return err
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.URL
	if target == nil || target.Host == "" {
		http.Error(w, "proxy requires absolute-form request URI", http.StatusBadRequest)
		return
	}
	host := target.Hostname()
	if !p.allowed(host) {
		http.Error(w, "blocked by sandbox-local network allowlist", http.StatusForbidden)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL = cloneURL(target)
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Proxy-Connection")
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPortDefault(r.Host, "443")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !p.allowed(host) {
		http.Error(w, "blocked by sandbox-local network allowlist", http.StatusForbidden)
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 15*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer target.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, buffered)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
	}()
	wg.Wait()
}

func (p *Proxy) allowed(host string) bool {
	canonical, ok := canonicalHost(host)
	if !ok {
		return false
	}
	for _, pattern := range p.policy.Deny {
		if matchPattern(canonical, pattern) {
			return false
		}
	}
	for _, pattern := range p.policy.Allow {
		if matchPattern(canonical, pattern) {
			return true
		}
	}
	return false
}

func splitHostPortDefault(value string, defaultPort string) (string, string, error) {
	if value == "" {
		return "", "", errors.New("missing host")
	}
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return host, port, nil
	}
	if strings.Contains(err.Error(), "missing port in address") {
		return strings.Trim(value, "[]"), defaultPort, nil
	}
	return "", "", err
}

func canonicalHost(host string) (string, bool) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" || strings.ContainsAny(host, "\x00\r\n\t /\\") {
		return "", false
	}
	lower := strings.ToLower(host)
	if addr, err := netip.ParseAddr(lower); err == nil {
		return addr.String(), true
	}
	for _, part := range strings.Split(lower, ".") {
		if part == "" {
			return "", false
		}
	}
	return strings.TrimSuffix(lower, "."), true
}

func validatePatterns(patterns []string) error {
	for _, pattern := range patterns {
		if _, err := normalizePattern(pattern); err != nil {
			return err
		}
	}
	return nil
}

func normalizePattern(pattern string) (string, error) {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if pattern == "" {
		return "", errors.New("empty network pattern")
	}
	if strings.Contains(pattern, "://") || strings.ContainsAny(pattern, "/:\x00\r\n\t ") {
		return "", fmt.Errorf("invalid network pattern %q", pattern)
	}
	if pattern == "*" || pattern == "*." {
		return "", fmt.Errorf("overly broad network pattern %q", pattern)
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		if strings.Count(base, ".") < 1 {
			return "", fmt.Errorf("wildcard network pattern %q is too broad", pattern)
		}
		for _, part := range strings.Split(base, ".") {
			if part == "" {
				return "", fmt.Errorf("invalid network pattern %q", pattern)
			}
		}
		return pattern, nil
	}
	if strings.Contains(pattern, "*") {
		return "", fmt.Errorf("invalid network wildcard pattern %q", pattern)
	}
	if _, ok := canonicalHost(pattern); !ok {
		return "", fmt.Errorf("invalid network pattern %q", pattern)
	}
	return pattern, nil
}

func matchPattern(host string, pattern string) bool {
	pattern, err := normalizePattern(pattern)
	if err != nil {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return host != base && strings.HasSuffix(host, "."+base)
	}
	return host == pattern
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func cloneURL(in *url.URL) *url.URL {
	out := *in
	return &out
}
