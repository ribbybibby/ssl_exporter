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

// ProbeFile collects certificate metrics from local files
func ProbeRemoteFile(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	errCh := make(chan error, 1)

	go func() {
		proxy := http.ProxyFromEnvironment
		if module.HTTPS.ProxyURL.URL != nil {
			proxy = http.ProxyURL(module.HTTPS.ProxyURL.URL)
		}

		tlsConfig, err := config.NewTLSConfig(&module.TLSConfig)
		if err != nil {
			errCh <- err
			return
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   tlsConfig,
				Proxy:             proxy,
				DisableKeepAlives: true,
			},
		}

		resp, err := client.Get(target)
		if err != nil {
			errCh <- err
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			errCh <- fmt.Errorf("failed to download file, status code: %d", resp.StatusCode)
			return
		}

		body, err := io.ReadAll(resp.Body)
		certs, err := decodeCertificates([]byte(body))

		errCh <- collectCertificateMetrics(certs, registry)
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context timeout, ran out of time")
	case err := <-errCh:
		return err
	}
}
