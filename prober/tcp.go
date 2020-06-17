package prober

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"

	pconfig "github.com/prometheus/common/config"
)

// ProbeTCP performs a tcp probe
func ProbeTCP(target string, module config.Module, timeout time.Duration) (*tls.ConnectionState, error) {
	tlsConfig, err := pconfig.NewTLSConfig(&module.TLSConfig)
	if err != nil {
		return nil, err
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	return &state, nil
}
