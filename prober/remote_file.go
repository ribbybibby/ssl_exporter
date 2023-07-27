package prober

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
)

// ProbeFile collects certificate metrics from local files
func ProbeRemoteFile(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	errCh := make(chan error, 1)

	go func() {
		tempFile, err := os.CreateTemp("", "download-*.tmp")
		if err != nil {
			errCh <- err
			return
		}
		defer tempFile.Close()

		proxy := http.ProxyFromEnvironment
		if module.HTTPS.ProxyURL.URL != nil {
			proxy = http.ProxyURL(module.HTTPS.ProxyURL.URL)
		}

		client := &http.Client{
			Transport: &http.Transport{
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

		// Copy the content of the response body to the temporary file
		_, err = io.Copy(tempFile, resp.Body)
		if err != nil {
			errCh <- err
			return
		}

		errCh <- collectFileMetrics(logger, []string{tempFile.Name()}, registry)
		defer os.Remove(tempFile.Name())
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context timeout, ran out of time")
	case err := <-errCh:
		return err
	}
}
