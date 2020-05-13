package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pconfig "github.com/prometheus/common/config"
	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"
)

// TestProbeHandlerHTTPS tests a typical HTTPS probe
func TestProbeHandlerHTTPS(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": config.Module{
				Prober: "https",
				TLSConfig: pconfig.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	rr, err := probe(server.URL, "https", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check success metric
	if ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1"); !ok {
		t.Errorf("expected `ssl_tls_connect_success 1`")
	}

	// Check probe metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"https\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"https\"} 1`")
	}

	// Check notAfter and notBefore metrics
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf(err.Error())
	}
	notAfter := strconv.FormatFloat(float64(cert.NotAfter.UnixNano()/1e9), 'g', -1, 64)
	if ok := strings.Contains(rr.Body.String(), "ssl_cert_not_after{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} "+notAfter); !ok {
		t.Errorf("expected `ssl_cert_not_after{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} " + notAfter + "`")
	}
	notBefore := strconv.FormatFloat(float64(cert.NotBefore.UnixNano()/1e9), 'g', -1, 64)
	if ok := strings.Contains(rr.Body.String(), "ssl_cert_not_before{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} "+notBefore); !ok {
		t.Errorf("expected `ssl_cert_not_before{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} " + notBefore + "`")
	}

	// Check TLS version metric
	ok := strings.Contains(rr.Body.String(), "ssl_tls_version_info{version=\"TLS 1.3\"} 1")
	if !ok {
		t.Errorf("expected `ssl_tls_version_info{version=\"TLS 1.3\"} 1`")
	}
}

func TestProbeHandlerHTTPSNoServer(t *testing.T) {
	rr, err := probe("localhost:6666", "https", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check success metric
	if ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0"); !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

// TestProbeHandlerHTTPSEmptyTarget tests a https probe with an empty target
func TestProbeHandlerHTTPSEmptyTarget(t *testing.T) {
	rr, err := probe("", "https", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if rr.Code != 400 {
		t.Fatalf("expected 400 status code, got %v", rr.Code)
	}
}

// TestProbeHandlerHTTPSSpaces tests an invalid address with spaces in it
func TestProbeHandlerHTTPSSpaces(t *testing.T) {
	rr, err := probe("with spaces", "https", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

// TestProbeHandlerHTTPSHTTP tests a https probe against a http server
func TestProbeHandlerHTTPSHTTP(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))

	server.Start()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(u.Host, "https", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

func TestProbeHandlerHTTPSClientAuthWrongClientCert(t *testing.T) {
	server, serverCertPEM, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	// Configure client auth on the server
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(serverCertPEM)

	server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	server.TLS.RootCAs = certPool
	server.TLS.ClientCAs = certPool

	server.StartTLS()
	defer server.Close()

	// Create a different cert/key pair that won't be accepted by the server
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().AddDate(0, 0, 1))

	// Create cert file
	certFile, err := test.WriteFile("cert.pem", certPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(certFile)

	// Create key file
	keyFile, err := test.WriteFile("key.pem", keyPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(keyFile)

	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": config.Module{
				Prober: "https",
				TLSConfig: pconfig.TLSConfig{
					CAFile:   caFile,
					CertFile: certFile,
					KeyFile:  keyFile,
				},
			},
		},
	}

	rr, err := probe(server.Listener.Addr().String(), "https", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

// TestProbeHandlerTCP tests a typical TCP probe
func TestProbeHandlerTCP(t *testing.T) {
	server, certPEM, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"tcp": config.Module{
				Prober: "tcp",
				TLSConfig: pconfig.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	rr, err := probe(server.Listener.Addr().String(), "tcp", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check success metric
	if ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1"); !ok {
		t.Errorf("expected `ssl_tls_connect_success 1`")
	}

	// Check probe metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"tcp\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"tcp\"} 1`")
	}

	// Check notAfter and notBefore metrics
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf(err.Error())
	}
	notAfter := strconv.FormatFloat(float64(cert.NotAfter.UnixNano()/1e9), 'g', -1, 64)
	if ok := strings.Contains(rr.Body.String(), "ssl_cert_not_after{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} "+notAfter); !ok {
		t.Errorf("expected `ssl_cert_not_after{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} " + notAfter + "`")
	}
	notBefore := strconv.FormatFloat(float64(cert.NotBefore.UnixNano()/1e9), 'g', -1, 64)
	if ok := strings.Contains(rr.Body.String(), "ssl_cert_not_before{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} "+notBefore); !ok {
		t.Errorf("expected `ssl_cert_not_before{cn=\"example.ribbybibby.me\",dnsnames=\",example.ribbybibby.me,example-2.ribbybibby.me,example-3.ribbybibby.me,\",emails=\",me@ribbybibby.me,example@ribbybibby.me,\",ips=\",127.0.0.1,::1,\",issuer_cn=\"example.ribbybibby.me\",ou=\",ribbybibbys org,\",serial_no=\"100\"} " + notBefore + "`")
	}
}

//  TestProbeHandlerTCPNoServer tests against a tcp server that doesn't exist
func TestProbeHandlerTCPNoServer(t *testing.T) {
	rr, err := probe("localhost:6666", "tcp", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check success metric
	if ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0"); !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

// TestProbeHandlerTCPEmptyTarget tests a TCP probe with an empty target
func TestProbeHandlerTCPEmptyTarget(t *testing.T) {
	rr, err := probe("", "tcp", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if rr.Code != 400 {
		t.Fatalf("expected 400 status code, got %v", rr.Code)
	}
}

// TestProbeHandlerTCPSpaces tests an invalid address with spaces in it
func TestProbeHandlerTCPSpaces(t *testing.T) {
	rr, err := probe("with spaces", "tcp", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

// TestProbeHandlerTCPHTTP tests a tcp probe against a HTTP server
func TestProbeHandlerTCPHTTP(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))

	server.Start()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(u.Host, "tcp", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

func TestProbeHandlerTCPExpired(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	// Create a certificate with a notAfter date in the past
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().AddDate(0, 0, -1))
	testcert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	server.TLS.Certificates = []tls.Certificate{testcert}

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"tcp": config.Module{
				Prober: "tcp",
				TLSConfig: pconfig.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	rr, err := probe(server.Listener.Addr().String(), "tcp", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

func TestProbeHandlerTCPExpiredInsecure(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	// Create a certificate with a notAfter date in the past
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().AddDate(0, 0, -1))
	testcert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf(err.Error())
	}
	server.TLS.Certificates = []tls.Certificate{testcert}

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"tcp": config.Module{
				Prober: "tcp",
				TLSConfig: pconfig.TLSConfig{
					CAFile:             caFile,
					InsecureSkipVerify: true,
				},
			},
		},
	}

	rr, err := probe(server.Listener.Addr().String(), "tcp", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 1`")
	}
}

// TestProbeHandlerDefaultModule tests that the default module uses the tcp prober
func TestProbeHandlerDefaultModule(t *testing.T) {
	rr, err := probe("localhost:6666", "", config.DefaultConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check probe metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"tcp\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"tcp\"} 1`")
	}
}

func TestProbeHandlerProxy(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	// Test with a proxy that doesn't exist first
	badProxyURL, err := url.Parse("http://localhost:6666")
	if err != nil {
		t.Fatalf(err.Error())
	}

	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": config.Module{
				Prober: "https",
				TLSConfig: pconfig.TLSConfig{
					CAFile: caFile,
				},
				HTTPS: config.HTTPSProbe{
					// Check with a bad proxy url initially
					ProxyURL: config.URL{URL: badProxyURL},
				},
			},
		},
	}

	rr, err := probe(server.URL, "https", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check success metric
	if ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0"); !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}

	// Test with an actual proxy server
	proxyServer, err := test.SetupHTTPProxyServer()
	if err != nil {
		t.Fatalf(err.Error())
	}

	proxyServer.Start()
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	conf = &config.Config{
		Modules: map[string]config.Module{
			"https": config.Module{
				Prober: "https",
				TLSConfig: pconfig.TLSConfig{
					CAFile: caFile,
				},
				HTTPS: config.HTTPSProbe{
					// Check with a valid URL
					ProxyURL: config.URL{URL: proxyURL},
				},
			},
		},
	}

	rr, err = probe(server.URL, "https", conf)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Check success metric
	if ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1"); !ok {
		t.Errorf("expected `ssl_tls_connect_success 1`")
	}
}

func probe(target, module string, conf *config.Config) (*httptest.ResponseRecorder, error) {
	uri := "/probe?target=" + target
	if module != "" {
		uri = uri + "&module=" + module
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, conf)
	})

	handler.ServeHTTP(rr, req)

	return rr, nil
}
