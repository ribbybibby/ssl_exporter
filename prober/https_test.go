package prober

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
	"github.com/ribbybibby/ssl_exporter/v2/test"
	"golang.org/x/crypto/ocsp"
)

// TestProbeHTTPS tests the typical case
func TestProbeHTTPS(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeHTTPSTimeout tests that the https probe respects the timeout in the
// context
func TestProbeHTTPSTimeout(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		fmt.Fprintln(w, "Hello world")
	})

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: config.TLSConfig{
			CAFile: caFile,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err == nil {
		t.Fatalf("Expected error but returned error was nil")
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
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), "https://localhost:"+u.Port(), module, registry); err == nil {
		t.Fatalf("expected error, but err was nil")
	}
}

// TestProbeHTTPSNoScheme tests that the probe is successful when the scheme is
// omitted from the target. The scheme should be added by the prober.
func TestProbeHTTPSNoScheme(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), u.Host, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeHTTPSServername tests that the probe is successful when the
// servername is provided in the TLS config
func TestProbeHTTPSServerName(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
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
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
			ServerName:         u.Hostname(),
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), "https://localhost:"+u.Port(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeHTTPSHTTP tests that the prober fails when hitting a HTTP server
func TestProbeHTTPSHTTP(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))
	server.Start()
	defer server.Close()

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, config.Module{}, registry); err == nil {
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
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			CertFile:           certFile,
			KeyFile:            keyFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
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
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			CertFile:           certFile,
			KeyFile:            keyFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err == nil {
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
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err == nil {
		t.Fatalf("expected error but err is nil")
	}
}

// TestProbeHTTPSExpiredInsecure tests that the probe succeeds with an expired server cert
// when skipping cert verification
func TestProbeHTTPSExpiredInsecure(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
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
		TLSConfig: config.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: true,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeHTTPSProxy tests the proxy_url field in the configuration
func TestProbeHTTPSProxy(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
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

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err == nil {
		t.Fatalf("expected error but err was nil")
	}

	// Test with the proxy url, this shouldn't return an error
	module.HTTPS.ProxyURL = config.URL{URL: proxyURL}

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeHTTPSOCSP tests a HTTPS probe with OCSP stapling
func TestProbeHTTPSOCSP(t *testing.T) {
	server, certPEM, keyPEM, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	key, err := newKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ocsp.CreateResponse(cert, cert, ocsp.Response{SerialNumber: big.NewInt(64), Status: 1}, key)
	if err != nil {
		t.Fatalf(err.Error())
	}
	server.TLS.Certificates[0].OCSPStaple = resp

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: config.TLSConfig{
			CAFile: caFile,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics(resp, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeHTTPSVerifiedChains tests the verified chain metrics returned by a
// https probe
func TestProbeHTTPSVerifiedChains(t *testing.T) {
	rootPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf(err.Error())
	}

	rootCertExpiry := time.Now().AddDate(0, 0, 5)
	rootCertTmpl := test.GenerateCertificateTemplate(rootCertExpiry)
	rootCertTmpl.IsCA = true
	rootCertTmpl.SerialNumber = big.NewInt(1)
	rootCert, rootCertPem := test.GenerateSelfSignedCertificateWithPrivateKey(rootCertTmpl, rootPrivateKey)

	olderRootCertExpiry := time.Now().AddDate(0, 0, 3)
	olderRootCertTmpl := test.GenerateCertificateTemplate(olderRootCertExpiry)
	olderRootCertTmpl.IsCA = true
	olderRootCertTmpl.SerialNumber = big.NewInt(2)
	olderRootCert, olderRootCertPem := test.GenerateSelfSignedCertificateWithPrivateKey(olderRootCertTmpl, rootPrivateKey)

	oldestRootCertExpiry := time.Now().AddDate(0, 0, 1)
	oldestRootCertTmpl := test.GenerateCertificateTemplate(oldestRootCertExpiry)
	oldestRootCertTmpl.IsCA = true
	oldestRootCertTmpl.SerialNumber = big.NewInt(3)
	oldestRootCert, oldestRootCertPem := test.GenerateSelfSignedCertificateWithPrivateKey(oldestRootCertTmpl, rootPrivateKey)

	serverCertExpiry := time.Now().AddDate(0, 0, 4)
	serverCertTmpl := test.GenerateCertificateTemplate(serverCertExpiry)
	serverCertTmpl.SerialNumber = big.NewInt(4)
	serverCert, serverCertPem, serverKey := test.GenerateSignedCertificate(serverCertTmpl, olderRootCert, rootPrivateKey)

	verifiedChains := [][]*x509.Certificate{
		[]*x509.Certificate{
			serverCert,
			rootCert,
		},
		[]*x509.Certificate{
			serverCert,
			olderRootCert,
		},
		[]*x509.Certificate{
			serverCert,
			oldestRootCert,
		},
	}

	caCertPem := bytes.Join([][]byte{oldestRootCertPem, olderRootCertPem, rootCertPem}, []byte(""))

	server, caFile, teardown, err := test.SetupHTTPSServerWithCertAndKey(
		caCertPem,
		serverCertPem,
		serverKey,
	)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	module := config.Module{
		TLSConfig: config.TLSConfig{
			CAFile: caFile,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPS(ctx, newTestLogger(), server.URL, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkCertificateMetrics(serverCert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkCRLMetrics([]byte{}, registry, t)
	checkVerifiedChainMetrics(verifiedChains, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}
