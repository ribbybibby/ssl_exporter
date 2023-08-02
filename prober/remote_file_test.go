package prober

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
	"github.com/ribbybibby/ssl_exporter/v2/test"
)

func TestProbeRemoteFileHTTP(t *testing.T) {
	testcertPEM, _ := test.GenerateTestCertificate(time.Now().AddDate(0, 0, 1))

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, string(testcertPEM[:]))
	}))

	server.Start()
	defer server.Close()

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeRemoteFile(ctx, newTestLogger(), server.URL+"/file", config.Module{}, registry); err != nil {
		t.Fatalf("error: %s", err)
	}
}

func TestProbeRemoteFileHTTPS(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, string(certPEM[:]))
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

	if err := ProbeRemoteFile(ctx, newTestLogger(), server.URL+"/file", module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}
}
