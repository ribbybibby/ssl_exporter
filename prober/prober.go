package prober

import (
	"context"

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
	}
)

// ProbeFn probes
type ProbeFn func(ctx context.Context, target string, module config.Module, registry *prometheus.Registry) error
