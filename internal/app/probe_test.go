package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateProbeTargetRequiresLiteralPrivateHTTPAddress(t *testing.T) {
	for _, target := range []string{
		"https://192.168.1.214:9876/",
		"http://example.com:9876/",
		"http://8.8.8.8:9876/",
		"http://admin:secret@192.168.1.214:9876/",
		"http://192.168.1.214/",
	} {
		if err := validateProbeTarget(target); err == nil {
			t.Errorf("validateProbeTarget(%q) unexpectedly succeeded", target)
		}
	}
	for _, target := range []string{"http://192.168.1.214:9876/", "http://127.0.0.1:9876/"} {
		if err := validateProbeTarget(target); err != nil {
			t.Errorf("validateProbeTarget(%q) = %v", target, err)
		}
	}
}

func TestProbeHTTPHeadDoesNotFollowRedirectOrSendGet(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodHead {
			t.Errorf("method = %s, want HEAD", r.Method)
		}
		w.Header().Set("Location", "http://8.8.8.8/")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	status, err := probeHTTPHead(context.Background(), server.URL+"/")
	if err != nil || status != http.StatusFound || requests != 1 {
		t.Fatalf("probeHTTPHead() = status %d, error %v, requests %d", status, err, requests)
	}
}
