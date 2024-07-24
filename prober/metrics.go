package prober

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
	v1 "k8s.io/api/core/v1"
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

	certs = uniq(certs)

	if len(certs) == 0 {
		return fmt.Errorf("No certificates found")
	}

	for _, cert := range certs {
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

func collectCRLMetrics(verifiedChains [][]*x509.Certificate, registry *prometheus.Registry) error {
	var (
		crlStatus = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "crl_status"),
				Help: "The status of the CRL check 0=Good 1=Revoked 2=Unknown",
			},
		)
		crlRevokeReason = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "crl_revoke_reason"),
				Help: "The reason code for revocation in the CRL as specified in RFC 5280 Section 5.3.1",
			},
		)
		crlRevokedAt = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "crl_revoked_at"),
				Help: "The revocationTime value in the CRL, expressed as a Unix Epoch Time",
			},
		)
		crlNumber = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "crl_number"),
				Help: "The value of the X.509 v2 cRLNumber extension in the CRL",
			},
		)
		crlThisUpdate = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "crl_this_update"),
				Help: "The thisUpdate value in the CRL, expressed as a Unix Epoch Time",
			},
		)
		crlNextUpdate = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "crl_next_update"),
				Help: "The nextUpdate value in the CRL, expressed as a Unix Epoch Time",
			},
		)
	)
	registry.MustRegister(
		crlStatus,
		crlRevokeReason,
		crlRevokedAt,
		crlNumber,
		crlThisUpdate,
		crlNextUpdate,
	)

	if len(verifiedChains) == 0 {
		crlStatus.Set(2)
		return nil
	}
	issuerIndex := 1
	if len(verifiedChains[0]) < 2 {
		issuerIndex = 0
	}

	cert := verifiedChains[0][0]
	issuer := verifiedChains[0][issuerIndex]

	crl, err := fetchCRL(cert, issuer)
	if err != nil {
		crlStatus.Set(2)
		return err
	}
	if crl == nil {
		crlStatus.Set(2)
		return nil
	}
	num, _ := new(big.Float).SetInt(crl.Number).Float64()
	crlNumber.Set(num)
	crlThisUpdate.Set(float64(crl.ThisUpdate.Unix()))
	crlNextUpdate.Set(float64(crl.NextUpdate.Unix()))
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			crlStatus.Set(1)
			crlRevokeReason.Set(float64(revokedCert.ReasonCode))
			crlRevokedAt.Set(float64(revokedCert.RevocationTime.Unix()))
			break
		}
	}
	return nil
}

func collectFileMetrics(logger log.Logger, files []string, registry *prometheus.Registry) error {
	var (
		totalCerts   []*x509.Certificate
		fileNotAfter = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "file_cert_not_after"),
				Help: "NotAfter expressed as a Unix Epoch Time for a certificate found in a file",
			},
			[]string{"file", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
		fileNotBefore = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "file_cert_not_before"),
				Help: "NotBefore expressed as a Unix Epoch Time for a certificate found in a file",
			},
			[]string{"file", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
	)
	registry.MustRegister(fileNotAfter, fileNotBefore)

	for _, f := range files {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			level.Debug(logger).Log("msg", fmt.Sprintf("Error reading file %s: %s", f, err))
			continue
		}
		certs, err := decodeCertificates(data)
		if err != nil {
			return err
		}
		totalCerts = append(totalCerts, certs...)
		for _, cert := range certs {
			labels := append([]string{f}, labelValues(cert)...)

			if !cert.NotAfter.IsZero() {
				fileNotAfter.WithLabelValues(labels...).Set(float64(cert.NotAfter.Unix()))
			}

			if !cert.NotBefore.IsZero() {
				fileNotBefore.WithLabelValues(labels...).Set(float64(cert.NotBefore.Unix()))
			}
		}
	}

	if len(totalCerts) == 0 {
		return fmt.Errorf("No certificates found")
	}

	return nil
}

func collectKubernetesSecretMetrics(secrets []v1.Secret, registry *prometheus.Registry) error {
	var (
		totalCerts         []*x509.Certificate
		kubernetesNotAfter = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "kubernetes_cert_not_after"),
				Help: "NotAfter expressed as a Unix Epoch Time for a certificate found in a kubernetes secret",
			},
			[]string{"namespace", "secret", "key", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
		kubernetesNotBefore = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "kubernetes_cert_not_before"),
				Help: "NotBefore expressed as a Unix Epoch Time for a certificate found in a kubernetes secret",
			},
			[]string{"namespace", "secret", "key", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
	)
	registry.MustRegister(kubernetesNotAfter, kubernetesNotBefore)

	for _, secret := range secrets {
		for _, key := range []string{"tls.crt", "ca.crt"} {
			data := secret.Data[key]
			if len(data) == 0 {
				continue
			}
			certs, err := decodeCertificates(data)
			if err != nil {
				return err
			}
			totalCerts = append(totalCerts, certs...)
			for _, cert := range certs {
				labels := append([]string{secret.Namespace, secret.Name, key}, labelValues(cert)...)

				if !cert.NotAfter.IsZero() {
					kubernetesNotAfter.WithLabelValues(labels...).Set(float64(cert.NotAfter.Unix()))
				}

				if !cert.NotBefore.IsZero() {
					kubernetesNotBefore.WithLabelValues(labels...).Set(float64(cert.NotBefore.Unix()))
				}
			}
		}
	}

	if len(totalCerts) == 0 {
		return fmt.Errorf("No certificates found")
	}

	return nil
}

func collectKubeconfigMetrics(logger log.Logger, kubeconfig KubeConfig, registry *prometheus.Registry) error {
	var (
		totalCerts         []*x509.Certificate
		kubeconfigNotAfter = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "kubeconfig", "cert_not_after"),
				Help: "NotAfter expressed as a Unix Epoch Time for a certificate found in a kubeconfig",
			},
			[]string{"kubeconfig", "name", "type", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
		kubeconfigNotBefore = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "kubeconfig", "cert_not_before"),
				Help: "NotBefore expressed as a Unix Epoch Time for a certificate found in a kubeconfig",
			},
			[]string{"kubeconfig", "name", "type", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"},
		)
	)
	registry.MustRegister(kubeconfigNotAfter, kubeconfigNotBefore)

	for _, c := range kubeconfig.Clusters {
		var data []byte
		var err error
		if c.Cluster.CertificateAuthorityData != "" {
			data, err = base64.StdEncoding.DecodeString(c.Cluster.CertificateAuthorityData)
			if err != nil {
				return err
			}
		} else if c.Cluster.CertificateAuthority != "" {
			data, err = ioutil.ReadFile(c.Cluster.CertificateAuthority)
			if err != nil {
				level.Debug(logger).Log("msg", fmt.Sprintf("Error reading file %s: %s", c.Cluster.CertificateAuthority, err))
				return err
			}
		}
		if data == nil {
			continue
		}
		certs, err := decodeCertificates(data)
		if err != nil {
			return err
		}
		totalCerts = append(totalCerts, certs...)
		for _, cert := range certs {
			labels := append([]string{kubeconfig.Path, c.Name, "cluster"}, labelValues(cert)...)

			if !cert.NotAfter.IsZero() {
				kubeconfigNotAfter.WithLabelValues(labels...).Set(float64(cert.NotAfter.Unix()))
			}

			if !cert.NotBefore.IsZero() {
				kubeconfigNotBefore.WithLabelValues(labels...).Set(float64(cert.NotBefore.Unix()))
			}
		}
	}

	for _, u := range kubeconfig.Users {
		var data []byte
		var err error
		if u.User.ClientCertificateData != "" {
			data, err = base64.StdEncoding.DecodeString(u.User.ClientCertificateData)
			if err != nil {
				return err
			}
		} else if u.User.ClientCertificate != "" {
			data, err = ioutil.ReadFile(u.User.ClientCertificate)
			if err != nil {
				level.Debug(logger).Log("msg", fmt.Sprintf("Error reading file %s: %s", u.User.ClientCertificate, err))
				return err
			}
		}
		if data == nil {
			continue
		}
		certs, err := decodeCertificates(data)
		if err != nil {
			return err
		}
		totalCerts = append(totalCerts, certs...)
		for _, cert := range certs {
			labels := append([]string{kubeconfig.Path, u.Name, "user"}, labelValues(cert)...)

			if !cert.NotAfter.IsZero() {
				kubeconfigNotAfter.WithLabelValues(labels...).Set(float64(cert.NotAfter.Unix()))
			}

			if !cert.NotBefore.IsZero() {
				kubeconfigNotBefore.WithLabelValues(labels...).Set(float64(cert.NotBefore.Unix()))
			}
		}
	}

	if len(totalCerts) == 0 {
		return fmt.Errorf("No certificates found")
	}

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

func fetchCRLDistributionPointFromCert(cert *x509.Certificate) string {
	for _, url := range cert.CRLDistributionPoints {
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			return url
		}
	}
	return ""
}

func fetchCRL(cert, issuer *x509.Certificate) (*x509.RevocationList, error) {
	crlURL := fetchCRLDistributionPointFromCert(cert)
	// the leaf certificate may not always contain a CRL distribution point, but its issuer should
	if crlURL == "" {
		crlURL = fetchCRLDistributionPointFromCert(issuer)
	}
	if crlURL == "" {
		// CA/B Forum Ballot SC-063 v4 requires a CRL distribution point, but that only applies for publicly trusted CAs
		return nil, nil
	}

	resp, err := http.Get(crlURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, err
	}
	if crl.NextUpdate.Before(time.Now()) {
		return nil, fmt.Errorf("CRL has expired")
	}
	return crl, nil
}
