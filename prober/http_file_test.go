package prober

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
	"github.com/ribbybibby/ssl_exporter/v2/test"
)

func TestProbeHTTPFile(t *testing.T) {
	testcertPEM, _ := test.GenerateTestCertificate(time.Now().AddDate(0, 0, 1))

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testcertPEM)
	}))

	server.Start()
	defer server.Close()

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPFile(ctx, newTestLogger(), server.URL+"/file", config.Module{}, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	cert, err := newCertificate(testcertPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
}

func TestProbeHTTPFile_NotCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("foobar"))
	}))

	server.Start()
	defer server.Close()

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPFile(ctx, newTestLogger(), server.URL+"/file", config.Module{}, registry); err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestProbeHTTPFile_NotFound(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	server.Start()
	defer server.Close()

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeHTTPFile(ctx, newTestLogger(), server.URL+"/file", config.Module{}, registry); err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestProbeHTTPFileHTTPS(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

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

	cert, err := newCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	checkCertificateMetrics(cert, registry, t)
}
