package prober

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
)

// ProbeHTTPFile performs a http_file probe
func ProbeHTTPFile(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	tlsConfig, err := config.NewTLSConfig(&module.TLSConfig)
	if err != nil {
		return err
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return err
	}

	// If server name isn't set, then use the target hostname
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = targetURL.Hostname()
	}

	proxy := http.ProxyFromEnvironment
	if module.HTTPS.ProxyURL.URL != nil {
		proxy = http.ProxyURL(module.HTTPS.ProxyURL.URL)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			Proxy:             proxy,
			DisableKeepAlives: true,
		},
	}

	// Issue a GET request to the target
	request, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return err
	}
	request = request.WithContext(ctx)
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_, err := io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			level.Error(logger).Log("msg", err)
		}
		resp.Body.Close()
	}()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	certs, err := decodeCertificates(data)
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates in response body")
	}

	return collectCertificateMetrics(certs, registry)
}
