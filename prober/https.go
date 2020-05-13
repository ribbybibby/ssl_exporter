package prober

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/common/log"
	"github.com/ribbybibby/ssl_exporter/config"

	pconfig "github.com/prometheus/common/config"
)

// ProbeHTTPS performs a https probe
func ProbeHTTPS(target string, module config.Module, timeout time.Duration) (*tls.ConnectionState, error) {
	if strings.HasPrefix(target, "http://") {
		return nil, fmt.Errorf("Target is using http scheme: %s", target)
	}

	if !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := pconfig.NewTLSConfig(&module.TLSConfig)
	if err != nil {
		return nil, err
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
		Timeout: timeout,
	}

	// Issue a GET request to the target
	resp, err := client.Get(targetURL.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		_, err := io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			log.Errorln(err)
		}
		resp.Body.Close()
	}()

	// Check if the response from the target is encrypted
	if resp.TLS == nil {
		return nil, fmt.Errorf("The response from %s is unencrypted", targetURL.String())
	}

	return resp.TLS, nil
}
