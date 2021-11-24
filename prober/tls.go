package prober

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/config"
)

// newTLSConfig sets up TLS config and instruments it with a function that
// collects metrics for the verified chain
func newTLSConfig(target string, registry *prometheus.Registry, cfg *config.TLSConfig) (*tls.Config, error) {
	tlsConfig, err := config.NewTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	if tlsConfig.ServerName == "" && target != "" {
		targetAddress, _, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		tlsConfig.ServerName = targetAddress
	}

	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		return collectConnectionStateMetrics(state, registry)
	}

	return tlsConfig, nil
}

func uniq(certs []*x509.Certificate) []*x509.Certificate {
	r := []*x509.Certificate{}

	for _, c := range certs {
		if !contains(r, c) {
			r = append(r, c)
		}
	}

	return r
}

func contains(certs []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range certs {
		if (c.SerialNumber.String() == cert.SerialNumber.String()) && (c.Issuer.CommonName == cert.Issuer.CommonName) {
			return true
		}
	}
	return false
}

func decodeCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certs, err
			}
			if !contains(certs, cert) {
				certs = append(certs, cert)
			}
		}
	}

	return certs, nil
}
