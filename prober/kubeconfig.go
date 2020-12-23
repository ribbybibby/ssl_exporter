package prober

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/config"
	"gopkg.in/yaml.v2"
)

type KubeConfigCluster struct {
	Name    string
	Cluster KubeConfigClusterCert
}

type KubeConfigClusterCert struct {
	CertificateAuthority     string `yaml:"certificate-authority"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
}

type KubeConfigUser struct {
	Name string
	User KubeConfigUserCert
}

type KubeConfigUserCert struct {
	ClientCertificate     string `yaml:"client-certificate"`
	ClientCertificateData string `yaml:"client-certificate-data"`
}

type KubeConfig struct {
	Path     string
	Clusters []KubeConfigCluster
	Users    []KubeConfigUser
}

// ProbeKubeconfig collects certificate metrics from kubeconfig files
func ProbeKubeconfig(ctx context.Context, target string, module config.Module, registry *prometheus.Registry) error {
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("kubeconfig not found: %s", target)
	}
	k, err := ParseKubeConfig(target)
	if err != nil {
		return err
	}
	k.Path = target
	err = collectKubeconfigMetrics(*k, registry)
	if err != nil {
		return err
	}
	return nil
}

func ParseKubeConfig(file string) (*KubeConfig, error) {
	k := &KubeConfig{}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal([]byte(data), k)
	if err != nil {
		return nil, err
	}

	return k, nil
}
