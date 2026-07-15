package netdetect

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPublicIPReturnsPublicAndSkipsPrivate(t *testing.T) {
	// A service echoing a private IP must be skipped (it is not a public IP), even
	// though it is a syntactically valid host; detection falls through to the next
	// service, which reports a routable public address.
	priv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("10.0.0.5\n"))
	}))
	defer priv.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("8.8.8.8\n"))
	}))
	defer good.Close()

	d := New()
	d.ExternalServices = []string{priv.URL, good.URL}
	ip, ok := d.PublicIP(2 * time.Second)
	if !ok || ip != "8.8.8.8" {
		t.Fatalf("PublicIP = %q, %v; want 8.8.8.8,true", ip, ok)
	}
}

func TestPublicIPAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := New()
	d.ExternalServices = []string{srv.URL}
	if ip, ok := d.PublicIP(2 * time.Second); ok {
		t.Errorf("expected no IP, got %q", ip)
	}
}

func TestLocalPublicIPFromMetadata(t *testing.T) {
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("8.8.4.4"))
	}))
	defer meta.Close()
	d := New()
	d.MetadataServices = []string{meta.URL}
	ip, ok := d.LocalPublicIP(2 * time.Second)
	if !ok || ip != "8.8.4.4" {
		t.Fatalf("LocalPublicIP = %q, %v; want 8.8.4.4,true", ip, ok)
	}
}

func TestMetadataPrivateIPRejected(t *testing.T) {
	// A metadata endpoint returning a private IP must be rejected (not public).
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("10.0.0.5"))
	}))
	defer meta.Close()
	d := New()
	d.MetadataServices = []string{meta.URL}
	// localInterfaceIP may or may not find a public IP on the test host; only
	// assert the metadata private IP itself is not returned.
	if ip, ok := d.LocalPublicIP(2 * time.Second); ok && ip == "10.0.0.5" {
		t.Error("private metadata IP must not be accepted")
	}
}

func TestFetchRespectsTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("1.2.3.4"))
	}))
	defer slow.Close()
	d := New()
	d.ExternalServices = []string{slow.URL}
	start := time.Now()
	_, ok := d.PublicIP(50 * time.Millisecond) // shorter than the server delay
	if ok {
		t.Error("expected timeout failure")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Errorf("did not time out promptly: %v", elapsed)
	}
}

func TestPublicIPAcceptsIPv6(t *testing.T) {
	// A v6-only host's echo service replies with a v6 address; it must be accepted,
	// not rejected as "not a public IPv4".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("2606:4700:4700::1111\n"))
	}))
	defer srv.Close()
	d := New()
	d.ExternalServices = []string{srv.URL}
	ip, ok := d.PublicIP(2 * time.Second)
	if !ok || ip != "2606:4700:4700::1111" {
		t.Fatalf("PublicIP = %q, %v; want the v6 address", ip, ok)
	}
}

func TestPublicIPRejectsNonPublicV6(t *testing.T) {
	// A link-local v6 from an echo service must be rejected, not fed into the invite.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("fe80::1"))
	}))
	defer srv.Close()
	d := New()
	d.ExternalServices = []string{srv.URL}
	if ip, ok := d.PublicIP(2 * time.Second); ok {
		t.Errorf("PublicIP accepted a link-local v6: %q", ip)
	}
}

func TestLocalPublicIPPrefersV4Metadata(t *testing.T) {
	// A v4 metadata answer wins immediately, before the interface scan (which is
	// where a v6 address would come from) is ever consulted.
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("8.8.4.4"))
	}))
	defer v4.Close()
	d := New()
	d.MetadataServices = []string{v4.URL}
	if ip, ok := d.LocalPublicIP(2 * time.Second); !ok || ip != "8.8.4.4" {
		t.Fatalf("LocalPublicIP = %q, %v; want the v4 metadata address to win", ip, ok)
	}
}
