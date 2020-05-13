package prober

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"

	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/log"
)

// ProbeTCP performs a tcp probe
func ProbeTCP(target string, module config.Module, timeout time.Duration) (*tls.ConnectionState, error) {
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("Error setting deadline")
	}

	if module.TCP.StartTLS != "" {
		err = startTLS(conn, module.TCP.StartTLS)
		if err != nil {
			return nil, err
		}
	}

	tlsConfig, err := pconfig.NewTLSConfig(&module.TLSConfig)
	if err != nil {
		return nil, err
	}

	if tlsConfig.ServerName == "" {
		targetAddress, _, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		tlsConfig.ServerName = targetAddress
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()

	return &state, nil
}

type queryResponse struct {
	expect string
	send   string
}

var (
	// These are the protocols for which I had servers readily available to test
	// against. There are plenty of other protocols that should be added here in
	// the future.
	//
	// See openssl s_client for more examples:
	//  https://github.com/openssl/openssl/blob/openssl-3.0.0-alpha3/apps/s_client.c#L2229-L2728
	startTLSqueryResponses = map[string][]queryResponse{
		"smtp": []queryResponse{
			queryResponse{
				expect: "^220",
			},
			queryResponse{
				send: "EHLO prober",
			},
			queryResponse{
				expect: "^250-STARTTLS",
			},
			queryResponse{
				send: "STARTTLS",
			},
			queryResponse{
				expect: "^220",
			},
		},
		"ftp": []queryResponse{
			queryResponse{
				expect: "^220",
			},
			queryResponse{
				send: "AUTH TLS",
			},
			queryResponse{
				expect: "^234",
			},
		},
		"imap": []queryResponse{
			queryResponse{
				expect: "OK",
			},
			queryResponse{
				send: ". CAPABILITY",
			},
			queryResponse{
				expect: "STARTTLS",
			},
			queryResponse{
				expect: "OK",
			},
			queryResponse{
				send: ". STARTTLS",
			},
			queryResponse{
				expect: "OK",
			},
		},
	}
)

// startTLS will send the STARTTLS command for the given protocol
func startTLS(conn net.Conn, proto string) error {
	var err error

	qr, ok := startTLSqueryResponses[proto]
	if !ok {
		return fmt.Errorf("STARTTLS is not supported for %s", proto)
	}

	scanner := bufio.NewScanner(conn)
	for _, qr := range qr {
		if qr.expect != "" {
			var match bool
			for scanner.Scan() {
				log.Debugf("read line: %s", scanner.Text())
				match, err = regexp.Match(qr.expect, scanner.Bytes())
				if err != nil {
					return err
				}
				if match {
					log.Debugf("regex: %s matched: %s", qr.expect, scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				return scanner.Err()
			}
			if !match {
				return fmt.Errorf("regex: %s didn't match: %s", qr.expect, scanner.Text())
			}
		}
		if qr.send != "" {
			log.Debugf("sending line: %s", qr.send)
			if _, err := fmt.Fprintf(conn, "%s\r\n", qr.send); err != nil {
				return err
			}
		}
	}
	return nil
}
