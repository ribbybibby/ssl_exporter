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

	dto "github.com/prometheus/client_model/go"
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
	expectedLabels := map[string]map[string]map[string]string{
		certFile: {
			"ssl_file_cert_not_after": {
				"file":      certFile,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			"ssl_file_cert_not_before": {
				"file":      certFile,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
		},
	}
	checkFileRegistryLabels(expectedLabels, mfs, t)

	expectedResults := map[string]map[string]float64{
		certFile: {
			"ssl_file_cert_not_after":  float64(cert.NotAfter.Unix()),
			"ssl_file_cert_not_before": float64(cert.NotBefore.Unix()),
		},
	}
	checkFileRegistryResults(expectedResults, mfs, t)
}

// Check if expected results are in the registry
func checkFileRegistryResults(expRes map[string]map[string]float64, mfs []*dto.MetricFamily, t *testing.T) {
	results := make(map[string]map[string]float64)
	for _, mf := range mfs {
		for _, metric := range mf.Metric {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "file" {
					if _, ok := results[l.GetValue()]; !ok {
						results[l.GetValue()] = make(map[string]float64)
					}
					results[l.GetValue()][mf.GetName()] = metric.GetGauge().GetValue()
				}
			}
		}
	}
	for expf, expr := range expRes {
		for expm, expv := range expr {
			if _, ok := results[expf]; !ok {
				t.Fatalf("Could not find results for file %v", expf)
			}
			v, ok := results[expf][expm]
			if !ok {
				t.Fatalf("Expected metric %v not found in returned metrics for file %v", expm, expf)
			}
			if v != expv {
				t.Fatalf("Expected: %v: %v, got: %v: %v for file %v", expm, expv, expm, v, expf)
			}
		}
	}
}

// Check if expected labels are in the registry
func checkFileRegistryLabels(expRes map[string]map[string]map[string]string, mfs []*dto.MetricFamily, t *testing.T) {
	results := make(map[string]map[string]map[string]string)
	for _, mf := range mfs {
		for _, metric := range mf.Metric {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "file" {
					if _, ok := results[l.GetValue()]; !ok {
						results[l.GetValue()] = make(map[string]map[string]string)
					}
					results[l.GetValue()][mf.GetName()] = make(map[string]string)
					for _, sl := range metric.GetLabel() {
						results[l.GetValue()][mf.GetName()][sl.GetName()] = sl.GetValue()
					}
				}
			}
		}
	}
	for expf, expr := range expRes {
		for expm, expl := range expr {
			if _, ok := results[expf]; !ok {
				t.Fatalf("Could not find results for file %v", expf)
			}
			l, ok := results[expf][expm]
			if !ok {
				t.Fatalf("Expected metric %v not found in returned metrics for file %v", expm, expf)
			}
			for expk, expv := range expl {
				v, ok := l[expk]
				if !ok {
					t.Fatalf("Expected label %v for metric %v not found in returned metrics for file %v", expk, expm, expf)
				}
				if v != expv {
					t.Fatalf("Expected %v{%q=%q}, got: %v{%q=%q} for file %v", expm, expk, expv, expm, expk, v, expf)
				}
			}
			if len(l) != len(expl) {
				t.Fatalf("Expected %v labels but got %v for metric %v and file %v", len(expl), len(l), expm, expf)
			}
		}
	}
}
