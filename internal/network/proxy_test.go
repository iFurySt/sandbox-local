package network

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/iFurySt/sandbox-local/internal/model"
)

func TestProxyAllowsMatchingHost(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	proxy, err := StartProxy(model.NetworkPolicy{
		Mode:  model.NetworkAllowlist,
		Allow: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close(context.Background())

	client := proxyClient(t, proxy.URL())
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, string(body))
	}
}

func TestProxyBlocksUnmatchedHost(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	proxy, err := StartProxy(model.NetworkPolicy{
		Mode:  model.NetworkAllowlist,
		Allow: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close(context.Background())

	client := proxyClient(t, proxy.URL())
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestValidateRejectsBroadWildcard(t *testing.T) {
	if err := validatePatterns([]string{"*"}); err == nil {
		t.Fatal("expected broad wildcard to be rejected")
	}
}

func TestWildcardDoesNotMatchBaseDomain(t *testing.T) {
	if matchPattern("example.com", "*.example.com") {
		t.Fatal("wildcard should not match base domain")
	}
	if !matchPattern("api.example.com", "*.example.com") {
		t.Fatal("wildcard should match subdomain")
	}
}

func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(parsed),
		},
	}
}
