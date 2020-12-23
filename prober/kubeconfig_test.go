package prober

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
)

// TestProbeFile tests a file
func TestProbeKubeconfig(t *testing.T) {
	cert, kubeconfig, err := createTestKubeconfig("", "kubeconfig")
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(kubeconfig)

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeKubeconfig(ctx, kubeconfig, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKubeconfigMetrics(cert, kubeconfig, registry, t)
}

// Create a certificate and write it to a file
func createTestKubeconfig(dir, filename string) (*x509.Certificate, string, error) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	clusterCert := KubeConfigClusterCert{CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(certPEM))}
	clusters := []KubeConfigCluster{KubeConfigCluster{Name: "kubernetes", Cluster: clusterCert}}
	userCert := KubeConfigUserCert{ClientCertificateData: base64.StdEncoding.EncodeToString([]byte(certPEM))}
	users := []KubeConfigUser{KubeConfigUser{Name: "kubernetes-admin", User: userCert}}
	k := KubeConfig{
		Clusters: clusters,
		Users:    users,
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	tmpFile, err := ioutil.TempFile(dir, filename)
	if err != nil {
		return nil, tmpFile.Name(), err
	}
	k.Path = tmpFile.Name()
	d, err := yaml.Marshal(&k)
	if err != nil {
		return nil, tmpFile.Name(), err
	}
	if _, err := tmpFile.Write(d); err != nil {
		return nil, tmpFile.Name(), err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, tmpFile.Name(), err
	}

	return cert, tmpFile.Name(), nil
}

// Check metrics
func checkKubeconfigMetrics(cert *x509.Certificate, kubeconfig string, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	ips := ","
	for _, ip := range cert.IPAddresses {
		ips = ips + ip.String() + ","
	}
	expectedResults := []*registryResult{
		&registryResult{
			Name: "ssl_kubeconfig_cert_not_after",
			LabelValues: map[string]string{
				"kubeconfig": kubeconfig,
				"name":       "kubernetes",
				"type":       "cluster",
				"serial_no":  cert.SerialNumber.String(),
				"issuer_cn":  cert.Issuer.CommonName,
				"cn":         cert.Subject.CommonName,
				"dnsnames":   "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":        ips,
				"emails":     "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":         "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotAfter.Unix()),
		},
		&registryResult{
			Name: "ssl_kubeconfig_cert_not_before",
			LabelValues: map[string]string{
				"kubeconfig": kubeconfig,
				"name":       "kubernetes",
				"type":       "cluster",
				"serial_no":  cert.SerialNumber.String(),
				"issuer_cn":  cert.Issuer.CommonName,
				"cn":         cert.Subject.CommonName,
				"dnsnames":   "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":        ips,
				"emails":     "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":         "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotBefore.Unix()),
		},
		&registryResult{
			Name: "ssl_kubeconfig_cert_not_after",
			LabelValues: map[string]string{
				"kubeconfig": kubeconfig,
				"name":       "kubernetes-admin",
				"type":       "user",
				"serial_no":  cert.SerialNumber.String(),
				"issuer_cn":  cert.Issuer.CommonName,
				"cn":         cert.Subject.CommonName,
				"dnsnames":   "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":        ips,
				"emails":     "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":         "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotAfter.Unix()),
		},
		&registryResult{
			Name: "ssl_kubeconfig_cert_not_before",
			LabelValues: map[string]string{
				"kubeconfig": kubeconfig,
				"name":       "kubernetes-admin",
				"type":       "user",
				"serial_no":  cert.SerialNumber.String(),
				"issuer_cn":  cert.Issuer.CommonName,
				"cn":         cert.Subject.CommonName,
				"dnsnames":   "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":        ips,
				"emails":     "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":         "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotBefore.Unix()),
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}
