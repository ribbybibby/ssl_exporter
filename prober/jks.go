package prober

import (
	"context"
	"fmt"

	"github.com/bmatcuk/doublestar/v2"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
)

// ProbeJKS collects certificate metrics from local java keystore files
func ProbeJKS(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	errCh := make(chan error, 1)

	if module.JKS.Password == "" {
		return fmt.Errorf("No password for jks configured")
	}

	go func() {
		files, err := doublestar.Glob(target)
		if err != nil {
			errCh <- err
			return
		}

		if len(files) == 0 {
			errCh <- fmt.Errorf("No java keystore files found")
		} else {
			errCh <- collectJKSMetrics(logger, files, registry, module.JKS.Password)
		}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context timeout, ran out of time")
	case err := <-errCh:
		return err
	}
}
