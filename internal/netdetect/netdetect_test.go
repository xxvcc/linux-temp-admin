package netdetect

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPublicIPReturnsValidHostAndSkipsInvalid(t *testing.T) {
	// First service returns a private IP (rejected by validate.Host? private is a
	// valid *host* syntactically) -> use a clearly-invalid one to force skip.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not a host!!\n"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("203.0.113.7\n"))
	}))
	defer good.Close()

	d := New()
	d.ExternalServices = []string{bad.URL, good.URL}
	ip, ok := d.PublicIP(2 * time.Second)
	if !ok || ip != "203.0.113.7" {
		t.Fatalf("PublicIP = %q, %v; want 203.0.113.7,true", ip, ok)
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
