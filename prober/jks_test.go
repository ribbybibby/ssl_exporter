package prober

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ribbybibby/ssl_exporter/v2/config"
	"github.com/ribbybibby/ssl_exporter/v2/test"

	"github.com/prometheus/client_golang/prometheus"
)

// TestProbeFile tests a java keystore file
func TestProbeJKSFile(t *testing.T) {
	cert, certFile, err := createTestJKSFile("", "tls*.keystore")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	module := config.Module{
		JKS: config.JKSProbe{
			Password: "changeit",
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeJKS(ctx, newTestLogger(), certFile, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkJKSFileMetrics(cert, certFile, registry, t)
}

// TestProbeFileGlob tests matching a java keystore file with a glob
func TestProbeJKSFileGlob(t *testing.T) {
	cert, certFile, err := createTestJKSFile("", "tls*.keystore")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	module := config.Module{
		JKS: config.JKSProbe{
			Password: "changeit",
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	glob := filepath.Dir(certFile) + "/*.keystore"

	if err := ProbeJKS(ctx, newTestLogger(), glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkJKSFileMetrics(cert, certFile, registry, t)
}

// TestProbeFileGlobDoubleStar tests matching a java keystore file with a ** glob
func TestProbeJKSFileGlobDoubleStar(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	cert, certFile, err := createTestJKSFile(tmpDir, "tls*.keystore")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	module := config.Module{
		JKS: config.JKSProbe{
			Password: "changeit",
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	glob := filepath.Dir(filepath.Dir(certFile)) + "/**/*.keystore"

	if err := ProbeJKS(ctx, newTestLogger(), glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkJKSFileMetrics(cert, certFile, registry, t)
}

// TestProbeFileGlobDoubleStarMultiple tests matching multiple java keystore files with a ** glob
func TestProbeJKSFileGlobDoubleStarMultiple(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.RemoveAll(tmpDir)

	tmpDir1, err := ioutil.TempDir(tmpDir, "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	cert1, certFile1, err := createTestJKSFile(tmpDir1, "1*.keystore")
	if err != nil {
		t.Fatalf(err.Error())
	}

	tmpDir2, err := ioutil.TempDir(tmpDir, "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	cert2, certFile2, err := createTestJKSFile(tmpDir2, "2*.keystore")
	if err != nil {
		t.Fatalf(err.Error())
	}

	module := config.Module{
		JKS: config.JKSProbe{
			Password: "changeit",
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	glob := tmpDir + "/**/*.keystore"

	if err := ProbeJKS(ctx, newTestLogger(), glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkJKSFileMetrics(cert1, certFile1, registry, t)
	checkJKSFileMetrics(cert2, certFile2, registry, t)
}

// Create a java keystore contains certificate and write it to a file
func createTestJKSFile(dir, filename string) (*x509.Certificate, string, error) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	tmpFile, err := ioutil.TempFile(dir, filename)
	if err != nil {
		return nil, tmpFile.Name(), err
	}
	jks := test.GenerateTestJKSWithCertificate([]*x509.Certificate{cert})
	if err := jks.Store(tmpFile, []byte("changeit")); err != nil {
		return nil, "", err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, tmpFile.Name(), err
	}

	return cert, tmpFile.Name(), nil
}

// Check metrics
func checkJKSFileMetrics(cert *x509.Certificate, certFile string, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	ips := ","
	for _, ip := range cert.IPAddresses {
		ips = ips + ip.String() + ","
	}
	expectedResults := []*registryResult{
		&registryResult{
			Name: "ssl_jks_cert_not_after",
			LabelValues: map[string]string{
				"hostname":  hostname(),
				"file":      certFile,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotAfter.Unix()),
		},
		&registryResult{
			Name: "ssl_jks_cert_not_before",
			LabelValues: map[string]string{
				"hostname":  hostname(),
				"file":      certFile,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotBefore.Unix()),
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}
