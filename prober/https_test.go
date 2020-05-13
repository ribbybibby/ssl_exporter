package prober

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	pconfig "github.com/prometheus/common/config"
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

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	state, err := ProbeHTTPS(server.URL, module, 5*time.Second)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if state == nil {
		t.Fatalf("expected state but got nil")
	}
}

// TestProbeHTTPSInvalidName tests hitting the server on an address which isn't
// in the SANs (localhost)
func TestProbeHTTPSInvalidName(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if _, err := ProbeHTTPS("https://localhost:"+u.Port(), module, 5*time.Second); err == nil {
		t.Fatalf("expected error, but err was nil")
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

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if _, err := ProbeHTTPS(u.Host, module, 5*time.Second); err != nil {
		t.Fatalf("error: %s", err)
	}
}

// TestProbeHTTPSServername tests that the probe is successful when the
// servername is provided in the TLS config
func TestProbeHTTPSServerName(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
			ServerName:         u.Hostname(),
		},
	}

	if _, err := ProbeHTTPS("https://localhost:"+u.Port(), module, 5*time.Second); err != nil {
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

	if _, err := ProbeHTTPS(server.URL, config.Module{}, 5*time.Second); err == nil {
		t.Fatalf("expected error, but err was nil")
	}
}

// TestProbeHTTPSClientAuth tests that the probe is successful when using client auth
func TestProbeHTTPSClientAuth(t *testing.T) {
	server, certPEM, keyPEM, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	// Configure client auth on the server
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	server.TLS.RootCAs = certPool
	server.TLS.ClientCAs = certPool

	server.StartTLS()
	defer server.Close()

	// Create cert file
	certFile, err := test.WriteFile("cert.pem", certPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	// Create key file
	keyFile, err := test.WriteFile("key.pem", keyPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(keyFile)

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			CertFile:           certFile,
			KeyFile:            keyFile,
			InsecureSkipVerify: false,
		},
	}

	state, err := ProbeHTTPS(server.URL, module, 5*time.Second)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if state == nil {
		t.Fatalf("expected state but got nil")
	}
}

// TestProbeHTTPSClientAuthWrongClientCert tests that the probe fails with a bad
// client certificate
func TestProbeHTTPSClientAuthWrongClientCert(t *testing.T) {
	server, serverCertPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	// Configure client auth on the server
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(serverCertPEM)

	server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	server.TLS.RootCAs = certPool
	server.TLS.ClientCAs = certPool

	server.StartTLS()
	defer server.Close()

	// Create a different cert/key pair that won't be accepted by the server
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().AddDate(0, 0, 1))

	// Create cert file
	certFile, err := test.WriteFile("cert.pem", certPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	// Create key file
	keyFile, err := test.WriteFile("key.pem", keyPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(keyFile)

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			CertFile:           certFile,
			KeyFile:            keyFile,
			InsecureSkipVerify: false,
		},
	}

	if _, err := ProbeHTTPS(server.URL, module, 5*time.Second); err == nil {
		t.Fatalf("expected error but err is nil")
	}
}

// TestProbeHTTPSExpired tests that the probe fails with an expired server cert
func TestProbeHTTPSExpired(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	// Create a certificate with a notAfter date in the past
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().AddDate(0, 0, -1))
	testcert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	server.TLS.Certificates = []tls.Certificate{testcert}

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	if _, err := ProbeHTTPS(server.URL, module, 5*time.Second); err == nil {
		t.Fatalf("expected error but err is nil")
	}
}

// TestProbeHTTPSExpiredInsecure tests that the probe succeeds with an expired server cert
// when skipping cert verification
func TestProbeHTTPSExpiredInsecure(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	// Create a certificate with a notAfter date in the past
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().AddDate(0, 0, -1))
	testcert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	server.TLS.Certificates = []tls.Certificate{testcert}

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: true,
		},
	}

	state, err := ProbeHTTPS(server.URL, module, 5*time.Second)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if state == nil {
		t.Fatalf("expected state but got nil")
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
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
		HTTPS: config.HTTPSProbe{
			// Test with a bad proxy url first
			ProxyURL: config.URL{URL: badProxyURL},
		},
	}

	_, err = ProbeHTTPS(server.URL, module, 5*time.Second)
	if err == nil {
		t.Fatalf("expected error but err was nil")
	}

	// Test with the proxy url, this shouldn't return an error
	module.HTTPS.ProxyURL = config.URL{URL: proxyURL}

	state, err := ProbeHTTPS(server.URL, module, 5*time.Second)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if state == nil {
		t.Fatalf("expected state but got nil")
	}
}
