package prober

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/crypto/ocsp"
)

type registryResult struct {
	Name        string
	LabelValues map[string]string
	Value       float64
}

func (rr *registryResult) String() string {
	var labels []string
	for k, v := range rr.LabelValues {
		labels = append(labels, k+"=\""+v+"\"")
	}
	m := rr.Name
	if len(labels) > 0 {
		m = fmt.Sprintf("%s{%s}", m, strings.Join(labels, ","))
	}
	return fmt.Sprintf("%s %f", m, rr.Value)
}

func checkRegistryResults(expectedResults []*registryResult, mfs []*dto.MetricFamily, t *testing.T) {
	for _, expRes := range expectedResults {
		checkRegistryResult(expRes, mfs, t)
	}
}

func checkRegistryResult(expRes *registryResult, mfs []*dto.MetricFamily, t *testing.T) {
	var results []*registryResult
	for _, mf := range mfs {
		for _, metric := range mf.Metric {
			result := &registryResult{
				Name:  mf.GetName(),
				Value: metric.GetGauge().GetValue(),
			}
			if len(metric.GetLabel()) > 0 {
				labelValues := make(map[string]string)
				for _, l := range metric.GetLabel() {
					labelValues[l.GetName()] = l.GetValue()
				}
				result.LabelValues = labelValues
			}
			results = append(results, result)
		}
	}
	var ok bool
	var resStr string
	for _, res := range results {
		resStr = resStr + "\n" + res.String()
		if reflect.DeepEqual(res, expRes) {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("Expected %s, got: %s", expRes.String(), resStr)
	}
}

func checkCertificateMetrics(cert *x509.Certificate, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	ips := ","
	for _, ip := range cert.IPAddresses {
		ips = ips + ip.String() + ","
	}
	expectedLabels := map[string]string{
		"serial_no": cert.SerialNumber.String(),
		"issuer_cn": cert.Issuer.CommonName,
		"cn":        cert.Subject.CommonName,
		"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
		"ips":       ips,
		"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
		"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
	}
	expectedResults := []*registryResult{
		&registryResult{
			Name:        "ssl_cert_not_after",
			LabelValues: expectedLabels,
			Value:       float64(cert.NotAfter.Unix()),
		},
		&registryResult{
			Name:        "ssl_cert_not_before",
			LabelValues: expectedLabels,
			Value:       float64(cert.NotBefore.Unix()),
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func checkVerifiedChainMetrics(verifiedChains [][]*x509.Certificate, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for i, chain := range verifiedChains {
		for _, cert := range chain {
			ips := ","
			for _, ip := range cert.IPAddresses {
				ips = ips + ip.String() + ","
			}
			expectedLabels := map[string]string{
				"chain_no":  strconv.Itoa(i),
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			}
			expectedResults := []*registryResult{
				&registryResult{
					Name:        "ssl_verified_cert_not_after",
					LabelValues: expectedLabels,
					Value:       float64(cert.NotAfter.Unix()),
				},
				&registryResult{
					Name:        "ssl_verified_cert_not_before",
					LabelValues: expectedLabels,
					Value:       float64(cert.NotBefore.Unix()),
				},
			}
			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func checkOCSPMetrics(resp []byte, registry *prometheus.Registry, t *testing.T) {
	var (
		stapled    float64
		status     float64
		nextUpdate float64
		thisUpdate float64
		revokedAt  float64
		producedAt float64
	)
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) > 0 {
		parsedResponse, err := ocsp.ParseResponse(resp, nil)
		if err != nil {
			t.Fatal(err)
		}
		stapled = 1
		status = float64(parsedResponse.Status)
		nextUpdate = float64(parsedResponse.NextUpdate.Unix())
		thisUpdate = float64(parsedResponse.ThisUpdate.Unix())
		revokedAt = float64(parsedResponse.RevokedAt.Unix())
		producedAt = float64(parsedResponse.ProducedAt.Unix())
	}
	expectedResults := []*registryResult{
		&registryResult{
			Name:  "ssl_ocsp_response_stapled",
			Value: stapled,
		},
		&registryResult{
			Name:  "ssl_ocsp_response_status",
			Value: status,
		},
		&registryResult{
			Name:  "ssl_ocsp_response_next_update",
			Value: nextUpdate,
		},
		&registryResult{
			Name:  "ssl_ocsp_response_this_update",
			Value: thisUpdate,
		},
		&registryResult{
			Name:  "ssl_ocsp_response_revoked_at",
			Value: revokedAt,
		},
		&registryResult{
			Name:  "ssl_ocsp_response_produced_at",
			Value: producedAt,
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func checkCRLMetrics(crlRaw []byte, registry *prometheus.Registry, t *testing.T) {
	var (
		status     float64
		reason     float64
		revokedAt  float64
		number     float64
		thisUpdate float64
		nextUpdate float64
	)
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(crlRaw) == 0 {
		expectedResults := []*registryResult{
			{
				Name:  "ssl_crl_status",
				Value: 2,
			},
		}
		checkRegistryResults(expectedResults, mfs, t)
		return
	}
	crl, err := x509.ParseRevocationList(crlRaw)
	if err != nil {
		t.Fatal(err)
	}
	number = float64(crl.Number.Int64())
	thisUpdate = float64(crl.ThisUpdate.Unix())
	nextUpdate = float64(crl.NextUpdate.Unix())
	if len(crl.RevokedCertificateEntries) > 0 {
		status = 1
		reason = float64(crl.RevokedCertificateEntries[0].ReasonCode)
		revokedAt = float64(crl.RevokedCertificateEntries[0].RevocationTime.Unix())
	}
	expectedResults := []*registryResult{
		{
			Name:  "ssl_crl_status",
			Value: status,
		},
		{
			Name:  "ssl_crl_revoke_reason",
			Value: reason,
		},
		{
			Name:  "ssl_crl_revoked_at",
			Value: revokedAt,
		},
		{
			Name:  "ssl_crl_number",
			Value: number,
		},
		{
			Name:  "ssl_crl_this_update",
			Value: thisUpdate,
		},
		{
			Name:  "ssl_crl_next_update",
			Value: nextUpdate,
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func checkTLSVersionMetrics(version string, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := []*registryResult{
		&registryResult{
			Name: "ssl_tls_version_info",
			LabelValues: map[string]string{
				"version": version,
			},
			Value: 1,
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func newCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	return x509.ParseCertificate(block.Bytes)
}

func newKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
