package prober

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"
)

// TestProbeHTTPS tests the typical case
func TestProbeHTTPS(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	module := config.Module{}

	tlsConfig, err := config.NewTLSConfig(&config.TLSConfig{
		CAFile: caFile,
	})

	state, err := ProbeHTTPS(server.URL, module, 5*time.Second, tlsConfig)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if state == nil {
		t.Fatalf("expected state but got nil")
	}
}

// TestProbeHTTPSNoScheme tests that the probe is successful when the scheme is
// omitted from the target. The scheme should be added by the prober.
func TestProbeHTTPSNoScheme(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	module := config.Module{}

	tlsConfig, err := config.NewTLSConfig(&config.TLSConfig{
		CAFile: caFile,
	})

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if _, err := ProbeHTTPS(u.Host, module, 5*time.Second, tlsConfig); err != nil {
		t.Fatalf("error: %s", err)
	}
}

// TestProbeHTTPSHTTP tests that the prober fails when hitting a HTTP server
func TestProbeHTTPSHTTP(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))
	server.Start()
	defer server.Close()

	if _, err := ProbeHTTPS(server.URL, config.Module{}, 5*time.Second, &tls.Config{}); err == nil {
		t.Fatalf("expected error, but err was nil")
	}
}

// TestProbeHTTPSProxy tests the proxy_url field in the configuration
func TestProbeHTTPSProxy(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	proxyServer, err := test.SetupHTTPProxyServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	server.StartTLS()
	defer server.Close()

	proxyServer.Start()
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	badProxyURL, err := url.Parse("http://localhost:6666")
	if err != nil {
		t.Fatalf(err.Error())
	}

	module := config.Module{
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
		HTTPS: config.HTTPSProbe{
			// Test with a bad proxy url first
			ProxyURL: config.URL{URL: badProxyURL},
		},
	}

	tlsConfig, err := config.NewTLSConfig(&config.TLSConfig{
		CAFile: caFile,
	})

	_, err = ProbeHTTPS(server.URL, module, 5*time.Second, tlsConfig)
	if err == nil {
		t.Fatalf("expected error but err was nil")
	}

	// Test with the proxy url, this shouldn't return an error
	module.HTTPS.ProxyURL = config.URL{URL: proxyURL}

	state, err := ProbeHTTPS(server.URL, module, 5*time.Second, tlsConfig)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if state == nil {
		t.Fatalf("expected state but got nil")
	}
}
