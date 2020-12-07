package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"
)

// TestProbeHandler tests that the probe handler sets the ssl_probe_success and
// ssl_prober metrics correctly
func TestProbeHandler(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": config.Module{
				Prober: "https",
				TLSConfig: config.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(u.Host, "https", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check probe success
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_success 1"); !ok {
		t.Errorf("expected `ssl_probe_success 1`")
	}

	// Check prober metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"https\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"https\"} 1`")
	}
}

// TestProbeHandler tests that the probe handler sets the ssl_probe_success and
// ssl_prober metrics correctly when the probe fails
func TestProbeHandlerFail(t *testing.T) {
	rr, err := probe("localhost:6666", "", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check probe success
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_success 0"); !ok {
		t.Errorf("expected `ssl_probe_success 0`")
	}

	// Check prober metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"tcp\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"tcp\"} 1`")
	}
}

func probe(target, module string, conf *config.Config) (*httptest.ResponseRecorder, error) {
	uri := "/probe?target=" + target
	if module != "" {
		uri = uri + "&module=" + module
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, conf)
	})

	handler.ServeHTTP(rr, req)

	return rr, nil
}
