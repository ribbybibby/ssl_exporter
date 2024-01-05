package prober

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
	"github.com/ribbybibby/ssl_exporter/v2/test"
)

func TestProbeHTTPFile(t *testing.T) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing cert: %s", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(certPEM)
	}))

	server.Start()
	defer server.Close()

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPFile(ctx, newTestLogger(), server.URL+"/file", config.Module{}, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkCertificateMetrics(cert, registry, t)
}

func TestProbeHTTPFile_HTTPS(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing cert: %s", err)
	}

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(certPEM)
	})

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

	if err := ProbeHTTPFile(ctx, newTestLogger(), server.URL+"/file", module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkCertificateMetrics(cert, registry, t)
}
