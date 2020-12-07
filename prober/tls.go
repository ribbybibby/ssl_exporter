package prober

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/ribbybibby/ssl_exporter/config"
)

var (
	// The nameservers in resolvConf are used to perform DANE verification.
	resolvConf = "/etc/resolv.conf"
)

// newTLSConfig sets up TLS config and instruments it with a function that
// collects metrics for the verified chain
func newTLSConfig(target string, registry *prometheus.Registry, cTLSConfig *config.TLSConfig) (*tls.Config, error) {
	tlsConfig, err := config.NewTLSConfig(cTLSConfig)
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

	// Override the standard verification with our own. Capture the original
	// value of InsecureSkipVerify so we can use it later on.
	insecure := tlsConfig.InsecureSkipVerify
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if !insecure {
			var verifiedChains [][]*x509.Certificate
			if cTLSConfig.DANEVerify {
				verifiedChains, err = verifyDANE(&state, target, tlsConfig)
				if err != nil {
					return err
				}
			} else {
				verifiedChains, err = verifyPKIX(&state, tlsConfig)
				if err != nil {
					return err
				}
			}
			if err := collectVerifiedChainMetrics(verifiedChains, registry); err != nil {
				return err
			}
		}

		return collectConnectionStateMetrics(state, registry)
	}

	return tlsConfig, nil
}

// verifyPKIX performs typical PKIX verification of the target certificates
func verifyPKIX(state *tls.ConnectionState, tlsConfig *tls.Config) ([][]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots:         tlsConfig.RootCAs,
		DNSName:       state.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	return state.PeerCertificates[0].Verify(opts)
}

// verifyDANE performs DANE verification
func verifyDANE(state *tls.ConnectionState, target string, tlsConfig *tls.Config) ([][]*x509.Certificate, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return [][]*x509.Certificate{}, err
	}
	name, err := dns.TLSAName(dns.Fqdn(host), port, "tcp")
	if err != nil {
		return [][]*x509.Certificate{}, err
	}

	c := &dns.Client{}

	cc, err := dns.ClientConfigFromFile(resolvConf)
	if err != nil {
		return [][]*x509.Certificate{}, err
	}
	if len(cc.Servers) == 0 {
		return [][]*x509.Certificate{}, fmt.Errorf("no nameservers found in %s", resolvConf)
	}

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Id:               dns.Id(),
		},
		Question: []dns.Question{
			dns.Question{
				Name:   name,
				Qtype:  dns.TypeTLSA,
				Qclass: dns.ClassINET,
			},
		},
	}

	for _, server := range cc.Servers {
		in, _, err := c.Exchange(m, server+":53")
		if err != nil {
			log.Errorln(err)
			continue
		}

		for _, rr := range in.Answer {
			tr, ok := rr.(*dns.TLSA)
			if !ok {
				continue
			}
			switch tr.Usage {
			case 0:
				// Record must be in the verified chain,
				// not including leaf AND must pass pkix
				verifiedChains, err := verifyPKIX(state, tlsConfig)
				if err == nil {
					for _, chain := range verifiedChains {
						for _, cert := range chain[1:] {
							if err := tr.Verify(cert); err == nil {
								return verifiedChains, nil
							}
						}
					}
				}
			case 1:
				// Must match leaf certificate
				// AND must pass pkix
				verifiedChains, err := verifyPKIX(state, tlsConfig)
				if err == nil {
					if err := tr.Verify(state.PeerCertificates[0]); err == nil {
						return verifiedChains, nil
					}
				}
			case 2:
				// Must be in peer certificate chain, not
				// including leaf
				verifiedChains, err := verifyChain(state.PeerCertificates)
				if err == nil {
					for _, chain := range verifiedChains {
						for _, cert := range chain[1:] {
							if err := tr.Verify(cert); err == nil {
								if err := state.PeerCertificates[0].VerifyHostname(tlsConfig.ServerName); err == nil {
									return verifiedChains, nil
								}
							}
						}
					}
				}
			case 3:
				// Must match leaf certificate
				if err := tr.Verify(state.PeerCertificates[0]); err == nil {
					return [][]*x509.Certificate{}, nil
				}
			}
		}
	}

	return [][]*x509.Certificate{}, fmt.Errorf("can't find matching TLSA record for %s", name)
}

// verifyChain performs PKIX verification against the chain presented by the
// server, without considering the root certificates of the client
func verifyChain(certs []*x509.Certificate) ([][]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	}
	opts.Roots.AddCert(certs[len(certs)-1])
	if len(certs) >= 3 {
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	return certs[0].Verify(opts)
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
