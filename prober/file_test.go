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

	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"

	"github.com/prometheus/client_golang/prometheus"
)

// TestProbeFile tests a file
func TestProbeFile(t *testing.T) {
	cert, certFile, err := createTestFile("", "tls*.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeFile(ctx, certFile, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkFileMetrics(cert, certFile, registry, t)
}

// TestProbeFileGlob tests matching a file with a glob
func TestProbeFileGlob(t *testing.T) {
	cert, certFile, err := createTestFile("", "tls*.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	glob := filepath.Dir(certFile) + "/*.crt"

	if err := ProbeFile(ctx, glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkFileMetrics(cert, certFile, registry, t)
}

// TestProbeFileGlobDoubleStar tests matching a file with a ** glob
func TestProbeFileGlobDoubleStar(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	cert, certFile, err := createTestFile(tmpDir, "tls*.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	glob := filepath.Dir(filepath.Dir(certFile)) + "/**/*.crt"

	if err := ProbeFile(ctx, glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkFileMetrics(cert, certFile, registry, t)
}

// TestProbeFileGlobDoubleStarMultiple tests matching multiple files with a ** glob
func TestProbeFileGlobDoubleStarMultiple(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.RemoveAll(tmpDir)

	tmpDir1, err := ioutil.TempDir(tmpDir, "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	cert1, certFile1, err := createTestFile(tmpDir1, "1*.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}

	tmpDir2, err := ioutil.TempDir(tmpDir, "testdir")
	if err != nil {
		t.Fatalf(err.Error())
	}
	cert2, certFile2, err := createTestFile(tmpDir2, "2*.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	glob := tmpDir + "/**/*.crt"

	if err := ProbeFile(ctx, glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkFileMetrics(cert1, certFile1, registry, t)
	checkFileMetrics(cert2, certFile2, registry, t)
}

// Create a certificate and write it to a file
func createTestFile(dir, filename string) (*x509.Certificate, string, error) {
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
	if _, err := tmpFile.Write(certPEM); err != nil {
		return nil, tmpFile.Name(), err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, tmpFile.Name(), err
	}

	return cert, tmpFile.Name(), nil
}

// Check metrics
func checkFileMetrics(cert *x509.Certificate, certFile string, registry *prometheus.Registry, t *testing.T) {
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
			Name: "ssl_file_cert_not_after",
			LabelValues: map[string]string{
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
			Name: "ssl_file_cert_not_before",
			LabelValues: map[string]string{
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
