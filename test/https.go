package test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

// SetupHTTPSServer sets up a server for testing with a generated cert and key
// pair
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

// SetupHTTPProxyServer sets up a proxy server
func SetupHTTPProxyServer() (*httptest.Server, error) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
			}
			go func() {
				defer destConn.Close()
				defer clientConn.Close()

				_, err := io.Copy(destConn, clientConn)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}

			}()
			go func() {
				defer clientConn.Close()
				defer destConn.Close()

				_, err := io.Copy(clientConn, destConn)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}

			}()
		} else {
			fmt.Fprintln(w, "Hello world")
		}
	}))

	return server, nil
}
