package prober

import (
	"context"
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/config"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	// Support oidc in kube config files
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

var (
	ErrKubeBadTarget = fmt.Errorf("Target secret must be provided in the form: <namespace>/<name>")
)

func ProbeKubernetes(ctx context.Context, target string, module config.Module, registry *prometheus.Registry) error {
	client, err := newKubeClient(module.Kubernetes.Kubeconfig)
	if err != nil {
		return err
	}

	return probeKubernetes(ctx, target, module, registry, client)
}

func probeKubernetes(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, client kubernetes.Interface) error {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ErrKubeBadTarget
	}

	ns := parts[0]
	name := parts[1]

	var tlsSecrets []v1.Secret
	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, secret := range secrets.Items {
		if secret.Type == "kubernetes.io/tls" {
			nMatch, err := doublestar.Match(ns, secret.Namespace)
			if err != nil {
				return err
			}
			sMatch, err := doublestar.Match(name, secret.Name)
			if err != nil {
				return err
			}
			if nMatch && sMatch {
				tlsSecrets = append(tlsSecrets, secret)
			}
		}
	}

	return collectKubernetesSecretMetrics(tlsSecrets, registry)
}

// newKubeClient returns a Kubernetes client (clientset) from the supplied
// kubeconfig path, the KUBECONFIG environment variable, the default config file
// location ($HOME/.kube/config) or from the in-cluster service account environment.
func newKubeClient(path string) (*kubernetes.Clientset, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		loadingRules.ExplicitPath = path
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}
