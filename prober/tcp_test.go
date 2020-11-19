package prober

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"
	"golang.org/x/crypto/ocsp"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
)

// TestProbeTCP tests the typical case
func TestProbeTCP(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatal(err)
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

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeTCPInvalidName tests hitting the server on an address which isn't
// in the SANs (localhost)
func TestProbeTCPInvalidName(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
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

	_, listenPort, _ := net.SplitHostPort(server.Listener.Addr().String())

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, "localhost:"+listenPort, module, registry); err == nil {
		t.Fatalf("expected error but err was nil")
	}
}

// TestProbeTCPServerName tests that the probe is successful when the
// servername is provided in the TLS config
func TestProbeTCPServerName(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	host, listenPort, _ := net.SplitHostPort(server.Listener.Addr().String())

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
			ServerName:         host,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, "localhost:"+listenPort, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeTCPExpired tests that the probe fails with an expired server cert
func TestProbeTCPExpired(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
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

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err == nil {
		t.Fatalf("expected error but err is nil")
	}
}

// TestProbeTCPExpiredInsecure tests that the probe succeeds with an expired server cert
// when skipping cert verification
func TestProbeTCPExpiredInsecure(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupTCPServer()
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

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeTCPStartTLSSMTP tests STARTTLS against a mock SMTP server
func TestProbeTCPStartTLSSMTP(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartSMTP()
	defer server.Close()

	module := config.Module{
		TCP: config.TCPProbe{
			StartTLS: "smtp",
		},
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeTCPStartTLSFTP tests STARTTLS against a mock FTP server
func TestProbeTCPStartTLSFTP(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartFTP()
	defer server.Close()

	module := config.Module{
		TCP: config.TCPProbe{
			StartTLS: "ftp",
		},
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeTCPStartTLSIMAP tests STARTTLS against a mock IMAP server
func TestProbeTCPStartTLSIMAP(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartIMAP()
	defer server.Close()

	module := config.Module{
		TCP: config.TCPProbe{
			StartTLS: "imap",
		},
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeTCPTimeout tests that the TCP probe respects the timeout in the
// context
func TestProbeTCPTimeout(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	server.StartTLSWait(time.Second * 3)
	defer server.Close()

	module := config.Module{
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err == nil {
		t.Fatalf("Expected error but returned error was nil")
	}
}

// TestProbeTCPOCSP tests a TCP probe with OCSP stapling
func TestProbeTCPOCSP(t *testing.T) {
	server, certPEM, keyPEM, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatal(err)
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
		TLSConfig: pconfig.TLSConfig{
			CAFile:             caFile,
			InsecureSkipVerify: false,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkCertificateMetrics(cert, registry, t)
	checkOCSPMetrics(resp, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}

// TestProbeTCPVerifiedChains tests the verified chain metrics returned by a tcp
// probe
func TestProbeTCPVerifiedChains(t *testing.T) {
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

	server, caFile, teardown, err := test.SetupTCPServerWithCertAndKey(
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
		TLSConfig: pconfig.TLSConfig{
			CAFile: caFile,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeTCP(ctx, server.Listener.Addr().String(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkCertificateMetrics(serverCert, registry, t)
	checkOCSPMetrics([]byte{}, registry, t)
	checkVerifiedChainMetrics(verifiedChains, registry, t)
	checkTLSVersionMetrics("TLS 1.3", registry, t)
}
