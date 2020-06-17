package test

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/prometheus/common/log"
)

// TCPServer allows manipulation of the tls.Config before starting the listener
type TCPServer struct {
	Listener net.Listener
	TLS      *tls.Config
	stopCh   chan struct{}
}

// StartTLS starts a listener that performs a TLS handshake
func (t *TCPServer) StartTLS() {
	go func() {
		ln := tls.NewListener(t.Listener, t.TLS)
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		// Immediately upgrade to TLS.
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			log.Errorln(err)
		} else {
			// Send some bytes before terminating the connection.
			fmt.Fprintf(conn, "Hello World!\n")
		}

		t.stopCh <- struct{}{}
	}()
}

// Close stops the server and closes the listener
func (t *TCPServer) Close() {
	<-t.stopCh
	t.Listener.Close()
}

// SetupTCPServer sets up a server for testing with a generated cert and key
// pair
func SetupTCPServer() (*TCPServer, []byte, []byte, string, func(), error) {
	var teardown func()

	testcertPEM, testkeyPEM := GenerateTestCertificate(time.Now().AddDate(0, 0, 1))

	caFile, err := WriteFile("certfile.pem", testcertPEM)
	if err != nil {
		return nil, testcertPEM, testkeyPEM, caFile, teardown, err
	}

	teardown = func() {
		os.Remove(caFile)
	}

	testcert, err := tls.X509KeyPair(testcertPEM, testkeyPEM)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode TLS testing keypair: %s\n", err))
	}

	tlsConfig := &tls.Config{
		ServerName:   "127.0.0.1",
		Certificates: []tls.Certificate{testcert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// Create server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, testcertPEM, testkeyPEM, caFile, teardown, err
	}

	server := &TCPServer{
		Listener: ln,
		TLS:      tlsConfig,
		stopCh:   make(chan (struct{})),
	}

	return server, testcertPEM, testkeyPEM, caFile, teardown, nil
}
