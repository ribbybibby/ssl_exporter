package prober

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
)

// ProbeHTTPFile collects certificate metrics from a remote file via http
func ProbeHTTPFile(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	proxy := http.ProxyFromEnvironment
	if module.HTTPFile.ProxyURL.URL != nil {
		proxy = http.ProxyURL(module.HTTPFile.ProxyURL.URL)
	}

	tlsConfig, err := config.NewTLSConfig(&module.TLSConfig)
	if err != nil {
		return fmt.Errorf("creating TLS config: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			Proxy:             proxy,
			DisableKeepAlives: true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("creating http request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("making http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	certs, err := decodeCertificates(body)
	if err != nil {
		return fmt.Errorf("decoding certificates from response body: %w", err)
	}

	return collectCertificateMetrics(certs, registry)
}
