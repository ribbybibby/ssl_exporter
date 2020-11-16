package prober

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestKubernetesProbe(t *testing.T) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 10))
	block, _ = pem.Decode([]byte(caPEM))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	fakeKubeClient := fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"ca.crt":  caPEM,
		},
		Type: "kubernetes.io/tls",
	})

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := probeKubernetes(ctx, "bar/foo", module, registry, fakeKubeClient); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKubernetesMetrics(cert, "bar", "foo", "tls.crt", registry, t)
	checkKubernetesMetrics(caCert, "bar", "foo", "ca.crt", registry, t)
}

func TestKubernetesProbeGlob(t *testing.T) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 10))
	block, _ = pem.Decode([]byte(caPEM))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certPEM2, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ = pem.Decode([]byte(certPEM2))
	cert2, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caPEM2, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 10))
	block, _ = pem.Decode([]byte(caPEM2))
	caCert2, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	fakeKubeClient := fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"ca.crt":  caPEM,
		},
		Type: "kubernetes.io/tls",
	},
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "fooz",
				Namespace: "baz",
			},
			Data: map[string][]byte{
				"tls.crt": certPEM2,
				"ca.crt":  caPEM2,
			},
			Type: "kubernetes.io/tls",
		})

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := probeKubernetes(ctx, "ba*/*", module, registry, fakeKubeClient); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKubernetesMetrics(cert, "bar", "foo", "tls.crt", registry, t)
	checkKubernetesMetrics(caCert, "bar", "foo", "ca.crt", registry, t)
	checkKubernetesMetrics(cert2, "baz", "fooz", "tls.crt", registry, t)
	checkKubernetesMetrics(caCert2, "baz", "fooz", "ca.crt", registry, t)
}

func TestKubernetesProbeBadTarget(t *testing.T) {
	fakeKubeClient := fake.NewSimpleClientset()

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := probeKubernetes(ctx, "bar/foo/bar", module, registry, fakeKubeClient); err != ErrKubeBadTarget {
		t.Fatalf("Expected error: %v, but got %v", ErrKubeBadTarget, err)
	}
}

func checkKubernetesMetrics(cert *x509.Certificate, namespace, name, key string, registry *prometheus.Registry, t *testing.T) {
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
			Name: "ssl_kubernetes_cert_not_after",
			LabelValues: map[string]string{
				"namespace": namespace,
				"secret":    name,
				"key":       key,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotAfter.Unix()),
		},
		&registryResult{
			Name: "ssl_kubernetes_cert_not_before",
			LabelValues: map[string]string{
				"namespace": namespace,
				"secret":    name,
				"key":       key,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotBefore.Unix()),
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}
