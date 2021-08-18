package test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// TCPServer allows manipulation of the tls.Config before starting the listener
type TCPServer struct {
	Listener net.Listener
	TLS      *tls.Config
	stopCh   chan struct{}
	logger   log.Logger
}

// StartTLS starts a listener that performs an immediate TLS handshake
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
			level.Error(t.logger).Log("msg", err)
		} else {
			// Send some bytes before terminating the connection.
			fmt.Fprintf(conn, "Hello World!\n")
		}

		t.stopCh <- struct{}{}
	}()
}

// StartTLSWait starts a listener and waits for duration 'd' before performing
// the TLS handshake
func (t *TCPServer) StartTLSWait(d time.Duration) {
	go func() {
		ln := tls.NewListener(t.Listener, t.TLS)
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		time.Sleep(d)

		if err := conn.(*tls.Conn).Handshake(); err != nil {
			level.Error(t.logger).Log(err)
		} else {
			// Send some bytes before terminating the connection.
			fmt.Fprintf(conn, "Hello World!\n")
		}

		t.stopCh <- struct{}{}
	}()
}

// StartSMTP starts a listener that negotiates a TLS connection with an smtp
// client using STARTTLS
func (t *TCPServer) StartSMTP() {
	go func() {
		conn, err := t.Listener.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			panic("Error setting deadline")
		}

		fmt.Fprintf(conn, "220 ESMTP StartTLS pseudo-server\n")
		if _, e := fmt.Fscanf(conn, "EHLO prober\n"); e != nil {
			panic("Error in dialog. No EHLO received.")
		}
		fmt.Fprintf(conn, "250-pseudo-server.example.net\n")
		fmt.Fprintf(conn, "250-STARTTLS\n")
		fmt.Fprintf(conn, "250 DSN\n")

		if _, e := fmt.Fscanf(conn, "STARTTLS\n"); e != nil {
			panic("Error in dialog. No (TLS) STARTTLS received.")
		}
		fmt.Fprintf(conn, "220 2.0.0 Ready to start TLS\n")

		// Upgrade to TLS.
		tlsConn := tls.Server(conn, t.TLS)
		if err := tlsConn.Handshake(); err != nil {
			level.Error(t.logger).Log("msg", err)
		}
		defer tlsConn.Close()

		t.stopCh <- struct{}{}
	}()
}

// StartFTP starts a listener that negotiates a TLS connection with an ftp
// client using AUTH TLS
func (t *TCPServer) StartFTP() {
	go func() {
		conn, err := t.Listener.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		fmt.Fprintf(conn, "220 Test FTP Service\n")
		if _, e := fmt.Fscanf(conn, "AUTH TLS\n"); e != nil {
			panic("Error in dialog. No AUTH TLS received.")
		}
		fmt.Fprintf(conn, "234 AUTH command ok. Expecting TLS Negotiation.\n")

		// Upgrade to TLS.
		tlsConn := tls.Server(conn, t.TLS)
		if err := tlsConn.Handshake(); err != nil {
			level.Error(t.logger).Log(err)
		}
		defer tlsConn.Close()

		t.stopCh <- struct{}{}
	}()
}

// StartIMAP starts a listener that negotiates a TLS connection with an imap
// client using STARTTLS
func (t *TCPServer) StartIMAP() {
	go func() {
		conn, err := t.Listener.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		fmt.Fprintf(conn, "* OK XIMAP ready for requests\n")
		if _, e := fmt.Fscanf(conn, ". CAPABILITY\n"); e != nil {
			panic("Error in dialog. No . CAPABILITY received.")
		}
		fmt.Fprintf(conn, "* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN STARTTLS\n")
		fmt.Fprintf(conn, ". OK CAPABILITY completed.\n")
		if _, e := fmt.Fscanf(conn, ". STARTTLS\n"); e != nil {
			panic("Error in dialog. No . STARTTLS received.")
		}
		fmt.Fprintf(conn, ". OK Begin TLS negotiation now.\n")

		// Upgrade to TLS.
		tlsConn := tls.Server(conn, t.TLS)
		if err := tlsConn.Handshake(); err != nil {
			level.Error(t.logger).Log("msg", err)
		}
		defer tlsConn.Close()

		t.stopCh <- struct{}{}
	}()
}

// StartPostgreSQL starts a listener that negotiates a TLS connection with an postgresql
// client using STARTTLS
func (t *TCPServer) StartPostgreSQL() {
	go func() {
		conn, err := t.Listener.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		sslRequestMessage := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

		buffer := make([]byte, len(sslRequestMessage))

		_, err = io.ReadFull(conn, buffer)
		if err != nil {
			panic("Error reading input from client")
		}

		if bytes.Compare(buffer, sslRequestMessage) != 0 {
			panic(fmt.Sprintf("Error in dialog. No %x received", buffer))
		}

		sslRequestResponse := []byte{0x53}

		if _, err := conn.Write(sslRequestResponse); err != nil {
			panic("Error writing response to client")
		}

		tlsConn := tls.Server(conn, t.TLS)
		if err := tlsConn.Handshake(); err != nil {
			level.Error(t.logger).Log("msg", err)
		}
		defer tlsConn.Close()

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
	testcertPEM, testkeyPEM := GenerateTestCertificate(time.Now().AddDate(0, 0, 1))

	server, caFile, teardown, err := SetupTCPServerWithCertAndKey(testcertPEM, testcertPEM, testkeyPEM)
	if err != nil {
		return nil, testcertPEM, testkeyPEM, caFile, teardown, err
	}

	return server, testcertPEM, testkeyPEM, caFile, teardown, nil
}

// SetupTCPServerWithCertAndKey sets up a server with the provided certs and key
func SetupTCPServerWithCertAndKey(caPEM, certPEM, keyPEM []byte) (*TCPServer, string, func(), error) {
	var teardown func()

	caFile, err := WriteFile("certfile.pem", caPEM)
	if err != nil {
		return nil, caFile, teardown, err
	}

	teardown = func() {
		os.Remove(caFile)
	}

	testCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, caFile, teardown, err
	}

	tlsConfig := &tls.Config{
		ServerName:   "127.0.0.1",
		Certificates: []tls.Certificate{testCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, caFile, teardown, err
	}

	server := &TCPServer{
		Listener: ln,
		TLS:      tlsConfig,
		stopCh:   make(chan (struct{})),
		logger:   log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)),
	}

	return server, caFile, teardown, err
}
