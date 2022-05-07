package prober

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
)

// ProbeHTTPS performs a https probe
func ProbeHTTPS(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	tlsConfig, err := newTLSConfig("", registry, &module.TLSConfig)
	if err != nil {
		return err
	}

	if strings.HasPrefix(target, "http://") {
		return fmt.Errorf("Target is using http scheme: %s", target)
	}

	if !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return err
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

	// Check if the response from the target is encrypted
	if resp.TLS == nil {
		return fmt.Errorf("The response from %s is unencrypted", targetURL.String())
	}

	return nil
}
