package prober

import (
	"net"
	"testing"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/test"
)

// TestProbeTCP tests the typical case
func TestProbeTCP(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	module := config.Module{}

	host, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig, err := config.NewTLSConfig(&config.TLSConfig{
		CAFile:     caFile,
		ServerName: host,
	})

	if _, err := ProbeTCP(server.Listener.Addr().String(), module, 10*time.Second, tlsConfig); err != nil {
		t.Fatalf("error: %s", err)
	}
}

// TestProbeTCPStartTLSSMTP tests STARTTLS against a mock SMTP server
func TestProbeTCPStartTLSSMTP(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartSMTP()
	defer server.Close()

	module := config.Module{
		TCP: config.TCPProbe{
			StartTLS: "smtp",
		},
	}

	host, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig, err := config.NewTLSConfig(&config.TLSConfig{
		CAFile:     caFile,
		ServerName: host,
	})

	if _, err := ProbeTCP(server.Listener.Addr().String(), module, 10*time.Second, tlsConfig); err != nil {
		t.Fatalf("error: %s", err)
	}
}

// TestProbeTCPStartTLSFTP tests STARTTLS against a mock FTP server
func TestProbeTCPStartTLSFTP(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartFTP()
	defer server.Close()

	module := config.Module{
		TCP: config.TCPProbe{
			StartTLS: "ftp",
		},
	}

	host, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig, err := config.NewTLSConfig(&config.TLSConfig{
		CAFile:     caFile,
		ServerName: host,
	})

	if _, err := ProbeTCP(server.Listener.Addr().String(), module, 10*time.Second, tlsConfig); err != nil {
		t.Fatalf("error: %s", err)
	}
}

// TestProbeTCPStartTLSIMAP tests STARTTLS against a mock IMAP server
func TestProbeTCPStartTLSIMAP(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupTCPServer()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer teardown()

	server.StartIMAP()
	defer server.Close()

	module := config.Module{
		TCP: config.TCPProbe{
			StartTLS: "imap",
		},
	}

	host, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig, err := config.NewTLSConfig(&config.TLSConfig{
		CAFile:     caFile,
		ServerName: host,
	})

	if _, err := ProbeTCP(server.Listener.Addr().String(), module, 10*time.Second, tlsConfig); err != nil {
		t.Fatalf("error: %s", err)
	}
}
