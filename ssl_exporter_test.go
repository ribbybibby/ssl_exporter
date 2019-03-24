package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestProbeHandler(t *testing.T) {
	certContent, err := ioutil.ReadFile("test/badssl.com-client.pem")
	if err != nil {
		t.Fatalf("Can't read test client certificate from disk")
	}

	keyContent, err := ioutil.ReadFile("test/badssl.com-client-key.pem")
	if err != nil {
		t.Fatalf("Can't read test client certificate key from disk")
	}

	keyBlock, _ := pem.Decode(keyContent)

	keyBlockDecrypted, err := x509.DecryptPEMBlock(keyBlock, []byte("badssl.com"))
	if err != nil {
		t.Fatalf("Issue decrypting test client key")
	}

	keyContent = pem.EncodeToMemory(&pem.Block{Type: keyBlock.Type, Bytes: keyBlockDecrypted})

	emptyRootCAs := x509.NewCertPool()

	certificate, err := tls.X509KeyPair(certContent, keyContent)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Test the behaviour of various target URIs
	//    'ok' denotes whether we expect a succesful tls connection
	cases := []struct {
		uri       string
		ok        bool
		tlsConfig *tls.Config
	}{
		// Test against an assumed valid, reachable and functioning HTTPS address
		{uri: "google.com:443", ok: true, tlsConfig: &tls.Config{}},
		// Test against a HTTP address
		{uri: "google.com:80", ok: false, tlsConfig: &tls.Config{}},
		// Test against an expired certificate when we're rejecting invalid certs
		{uri: "expired.badssl.com:443", ok: false, tlsConfig: &tls.Config{}},
		// Test against an expired certificate when we're accepting invalid certs
		{uri: "expired.badssl.com:443", ok: true, tlsConfig: &tls.Config{InsecureSkipVerify: true}},
		// Test against a target with no port
		{uri: "google.com", ok: true, tlsConfig: &tls.Config{}},
		// Test against a string with spaces
		{uri: "with spaces", ok: false, tlsConfig: &tls.Config{}},
		// Test against nothing
		{uri: "", ok: false, tlsConfig: &tls.Config{}},
		// Test with client authentication
		{uri: "client.badssl.com:443", ok: true, tlsConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}},
		// Test with an empty root CA bundle
		{uri: "google.com:443", ok: false, tlsConfig: &tls.Config{RootCAs: emptyRootCAs}},
		// Test with a https scheme
		{uri: "https://google.com", ok: true, tlsConfig: &tls.Config{}},
		// Test with a https scheme and port
		{uri: "https://google.com:443", ok: true, tlsConfig: &tls.Config{}},
	}

	fmt.Println("Note: The error logs in these tests are expected. One of the important tests is that we return the expected body, even in the face of errors.")

	successMetricRegexp, err := regexp.Compile("(ssl_tls_connect_success [0-1])")
	if err != nil {
		t.Fatalf("Error compiling success metric: " + err.Error())
	}

	for _, test := range cases {

		uri := "/probe?target=" + test.uri
		req, err := http.NewRequest("GET", uri, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			probeHandler(w, r, test.tlsConfig)
		})

		handler.ServeHTTP(rr, req)

		// We should always return a 200, no matter what
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}

		// Make sure we're getting the ssl_tls_connect_success metric back
		if !successMetricRegexp.MatchString(rr.Body.String()) {
			t.Errorf("can't find ssl_tls_connect_success metric in response body w/ %q", uri)
		}

		// Make sure we're getting the result we expect from ssl_tls_connect_success
		ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1")
		if test.ok && !ok {
			t.Errorf("expected tls connection to succeed but it failed w/ %q", uri)
		}
		if !test.ok && ok {
			t.Errorf("expected tls connection to fail but it succeeded w/ %q", uri)
		}

	}
}
