package prober

import (
	"context"
	"fmt"

	"github.com/bmatcuk/doublestar/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/config"
)

func ProbeFile(ctx context.Context, target string, module config.Module, registry *prometheus.Registry) error {
	errCh := make(chan error, 1)

	go func() {
		files, err := doublestar.Glob(target)
		if err != nil {
			errCh <- err
			return
		}

		if len(files) == 0 {
			errCh <- fmt.Errorf("No files found")
		} else {
			errCh <- collectFileMetrics(files, registry)
		}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context timeout, ran out of time")
	case err := <-errCh:
		return err
	}
}
