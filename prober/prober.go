package prober

import (
	"context"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/config"
)

var (
	// Probers maps a friendly name to a corresponding probe function
	Probers = map[string]ProbeFn{
		"https":      ProbeHTTPS,
		"http":       ProbeHTTPS,
		"tcp":        ProbeTCP,
		"file":       ProbeFile,
		"kubernetes": ProbeKubernetes,
		"kubeconfig": ProbeKubeconfig,
	}
)

// ProbeFn probes
type ProbeFn func(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error
