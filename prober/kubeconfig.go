package prober

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

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
	k.Path = file
	clusters := []KubeConfigCluster{}
	users := []KubeConfigUser{}
	for _, c := range k.Clusters {
		// Path is relative to kubeconfig path
		if c.Cluster.CertificateAuthority != "" && !filepath.IsAbs(c.Cluster.CertificateAuthority) {
			newPath := filepath.Join(filepath.Dir(k.Path), c.Cluster.CertificateAuthority)
			c.Cluster.CertificateAuthority = newPath
		}
		clusters = append(clusters, c)
	}
	for _, u := range k.Users {
		// Path is relative to kubeconfig path
		if u.User.ClientCertificate != "" && !filepath.IsAbs(u.User.ClientCertificate) {
			newPath := filepath.Join(filepath.Dir(k.Path), u.User.ClientCertificate)
			u.User.ClientCertificate = newPath
		}
		users = append(users, u)
	}
	k.Clusters = clusters
	k.Users = users
	return k, nil
}
