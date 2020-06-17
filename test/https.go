package test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

// SetupHTTPSServer sets up a server for testing with a generated cert and key
// pair. It returns the server, the cert and key, the path to the ca file and a
// function to clean up the server.
func SetupHTTPSServer() (*httptest.Server, []byte, []byte, string, func(), error) {
	var teardown func()

	testcertPEM, testkeyPEM := GenerateTestCertificate(time.Now().AddDate(0, 0, 1))

	caFile, err := WriteFile("certfile.pem", testcertPEM)
	if err != nil {
		return nil, testcertPEM, testkeyPEM, caFile, teardown, err
	}

	teardown = func() {
		os.Remove(caFile)
	}

	// Create server
	testcert, err := tls.X509KeyPair(testcertPEM, testkeyPEM)
	if err != nil {
		return nil, testcertPEM, testkeyPEM, caFile, teardown, err
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{testcert},
	}

	return server, testcertPEM, testkeyPEM, caFile, teardown, nil
}
