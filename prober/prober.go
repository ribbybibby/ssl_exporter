package prober

import (
	"crypto/tls"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"
)

var (
	// Probers maps a friendly name to a corresponding probe function
	Probers = map[string]ProbeFn{
		"https": ProbeHTTPS,
		"http":  ProbeHTTPS,
		"tcp":   ProbeTCP,
	}
)

// ProbeFn probes
type ProbeFn func(target string, module config.Module, timeout time.Duration) (*tls.ConnectionState, error)
