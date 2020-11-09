package prober

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/ribbybibby/ssl_exporter/config"
)

// ProbeTCP performs a tcp probe
func ProbeTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry) error {
	tlsConfig, err := newTLSConfig(target, registry, &module.TLSConfig)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("Error setting deadline")
	}

	if module.TCP.StartTLS != "" {
		err = startTLS(conn, module.TCP.StartTLS)
		if err != nil {
			return err
		}
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	return tlsConn.Handshake()
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
