package prober

import (
	"crypto/tls"
	"crypto/x509"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

const (
	namespace = "ssl"
)

func collectConnectionStateMetrics(state tls.ConnectionState, registry *prometheus.Registry) error {
	if err := collectTLSVersionMetrics(state.Version, registry); err != nil {
		return err
	}

	if err := collectCertificateMetrics(state.PeerCertificates, registry); err != nil {
		return err
	}

	if err := collectVerifiedChainMetrics(state.VerifiedChains, registry); err != nil {
		return err
	}

	return collectOCSPMetrics(state.OCSPResponse, registry)
}

func collectTLSVersionMetrics(version uint16, registry *prometheus.Registry) error {
	var (
		tlsVersion = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "tls_version_info"),
				Help: "The TLS version used",
			},
			[]string{"version"},
		)
	)
	registry.MustRegister(tlsVersion)

	var v string
	switch version {
	case tls.VersionTLS10:
		v = "TLS 1.0"
	case tls.VersionTLS11:
		v = "TLS 1.1"
	case tls.VersionTLS12:
		v = "TLS 1.2"
	case tls.VersionTLS13:
		v = "TLS 1.3"
	default:
		v = "unknown"
	}

	tlsVersion.WithLabelValues(v).Set(1)

	return nil
}

func collectCertificateMetrics(certs []*x509.Certificate, registry *prometheus.Registry) error {
	var (
		notAfter = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "cert_not_after"),
				Help: "NotAfter expressed as a Unix Epoch Time",
			},
			[]string{"serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
		notBefore = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "cert_not_before"),
				Help: "NotBefore expressed as a Unix Epoch Time",
			},
			[]string{"serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
	)
	registry.MustRegister(notAfter, notBefore)

	for _, cert := range uniq(certs) {
		labels := labelValues(cert)

		if !cert.NotAfter.IsZero() {
			notAfter.WithLabelValues(labels...).Set(float64(cert.NotAfter.Unix()))
		}

		if !cert.NotBefore.IsZero() {
			notBefore.WithLabelValues(labels...).Set(float64(cert.NotBefore.Unix()))
		}
	}

	return nil
}

func collectVerifiedChainMetrics(verifiedChains [][]*x509.Certificate, registry *prometheus.Registry) error {
	var (
		verifiedNotAfter = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "verified_cert_not_after"),
				Help: "NotAfter expressed as a Unix Epoch Time",
			},
			[]string{"chain_no", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
		verifiedNotBefore = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "verified_cert_not_before"),
				Help: "NotBefore expressed as a Unix Epoch Time",
			},
			[]string{"chain_no", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
	)
	registry.MustRegister(verifiedNotAfter, verifiedNotBefore)

	sort.Slice(verifiedChains, func(i, j int) bool {
		iExpiry := time.Time{}
		for _, cert := range verifiedChains[i] {
			if (iExpiry.IsZero() || cert.NotAfter.Before(iExpiry)) && !cert.NotAfter.IsZero() {
				iExpiry = cert.NotAfter
			}
		}
		jExpiry := time.Time{}
		for _, cert := range verifiedChains[j] {
			if (jExpiry.IsZero() || cert.NotAfter.Before(jExpiry)) && !cert.NotAfter.IsZero() {
				jExpiry = cert.NotAfter
			}
		}

		return iExpiry.After(jExpiry)
	})

	for i, chain := range verifiedChains {
		chain = uniq(chain)
		for _, cert := range chain {
			chainNo := strconv.Itoa(i)
			labels := append([]string{chainNo}, labelValues(cert)...)

			if !cert.NotAfter.IsZero() {
				verifiedNotAfter.WithLabelValues(labels...).Set(float64(cert.NotAfter.Unix()))
			}

			if !cert.NotBefore.IsZero() {
				verifiedNotBefore.WithLabelValues(labels...).Set(float64(cert.NotBefore.Unix()))
			}
		}
	}

	return nil
}

func collectOCSPMetrics(ocspResponse []byte, registry *prometheus.Registry) error {
	var (
		ocspStapled = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "ocsp_response_stapled"),
				Help: "If the connection state contains a stapled OCSP response",
			},
		)
		ocspStatus = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "ocsp_response_status"),
				Help: "The status in the OCSP response 0=Good 1=Revoked 2=Unknown",
			},
		)
		ocspProducedAt = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "ocsp_response_produced_at"),
				Help: "The producedAt value in the OCSP response, expressed as a Unix Epoch Time",
			},
		)
		ocspThisUpdate = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "ocsp_response_this_update"),
				Help: "The thisUpdate value in the OCSP response, expressed as a Unix Epoch Time",
			},
		)
		ocspNextUpdate = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "ocsp_response_next_update"),
				Help: "The nextUpdate value in the OCSP response, expressed as a Unix Epoch Time",
			},
		)
		ocspRevokedAt = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "ocsp_response_revoked_at"),
				Help: "The revocationTime value in the OCSP response, expressed as a Unix Epoch Time",
			},
		)
	)
	registry.MustRegister(
		ocspStapled,
		ocspStatus,
		ocspProducedAt,
		ocspThisUpdate,
		ocspNextUpdate,
		ocspRevokedAt,
	)

	if len(ocspResponse) == 0 {
		return nil
	}

	resp, err := ocsp.ParseResponse(ocspResponse, nil)
	if err != nil {
		return err
	}

	ocspStapled.Set(1)
	ocspStatus.Set(float64(resp.Status))
	ocspProducedAt.Set(float64(resp.ProducedAt.Unix()))
	ocspThisUpdate.Set(float64(resp.ThisUpdate.Unix()))
	ocspNextUpdate.Set(float64(resp.NextUpdate.Unix()))
	ocspRevokedAt.Set(float64(resp.RevokedAt.Unix()))

	return nil
}

func labelValues(cert *x509.Certificate) []string {
	return []string{
		cert.SerialNumber.String(),
		cert.Issuer.CommonName,
		cert.Subject.CommonName,
		dnsNames(cert),
		ipAddresses(cert),
		emailAddresses(cert),
		organizationalUnits(cert),
	}
}

func dnsNames(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return "," + strings.Join(cert.DNSNames, ",") + ","
	}

	return ""
}

func emailAddresses(cert *x509.Certificate) string {
	if len(cert.EmailAddresses) > 0 {
		return "," + strings.Join(cert.EmailAddresses, ",") + ","
	}

	return ""
}

func ipAddresses(cert *x509.Certificate) string {
	if len(cert.IPAddresses) > 0 {
		ips := ","
		for _, ip := range cert.IPAddresses {
			ips = ips + ip.String() + ","
		}
		return ips
	}

	return ""
}

func organizationalUnits(cert *x509.Certificate) string {
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ","
	}

	return ""
}
