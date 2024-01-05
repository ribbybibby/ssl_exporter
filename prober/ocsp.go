package prober

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
	"golang.org/x/crypto/ocsp"
)

// ProbeOCSP performs a OCSP probe
func ProbeOCSP(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	cert, err := readCert(module.OCSP.ClientCert)
	if err != nil {
		return err
	}

	issuerCert, err := readCert(module.OCSP.IssuingCert)
	if err != nil {
		return err
	}

	ocspURL := "http://" + target + module.OCSP.Path

	buffer, err := ocsp.CreateRequest(cert, issuerCert, &ocsp.RequestOptions{
		Hash: crypto.SHA1,
	})
	if err != nil {
		return fmt.Errorf("creating ocsp request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewBuffer(buffer))
	if err != nil {
		return fmt.Errorf("creating http request: %w", err)
	}

	ocspUrl, err := url.Parse(ocspURL)
	if err != nil {
		return fmt.Errorf("parsing ocsp url: %w", err)
	}

	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	req.Header.Add("host", ocspUrl.Host)
	req = req.WithContext(ctx)

	// Make OCSP request
	httpResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("making ocsp request: %w", err)
	}

	defer httpResponse.Body.Close()

	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	return collectOCSPMetrics(output, registry)
}

func readCert(path string) (*x509.Certificate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	defer file.Close()

	b, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	// PEM to DER
	block, _ := pem.Decode([]byte(b))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate %s: %w", path, err)
	}

	return cert, nil
}
