package prober

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
)

// ProbeTCP performs a tcp probe
func ProbeTCP(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
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
		err = startTLS(logger, conn, module.TCP.StartTLS)
		if err != nil {
			return err
		}
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	return tlsConn.Handshake()
}

type queryResponse struct {
	expect      string
	send        string
	sendBytes   []byte
	expectBytes []byte
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
		"postgres": []queryResponse{
			queryResponse{
				sendBytes: []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f},
			},
			queryResponse{
				expectBytes: []byte{0x53},
			},
		},
		"pop3": []queryResponse{
			queryResponse{
				expect: "OK",
			},
			queryResponse{
				send: "STLS",
			},
			queryResponse{
				expect: "OK",
			},
		},
	}
)

// startTLS will send the STARTTLS command for the given protocol
func startTLS(logger log.Logger, conn net.Conn, proto string) error {
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
				level.Debug(logger).Log("msg", fmt.Sprintf("read line: %s", scanner.Text()))
				match, err = regexp.Match(qr.expect, scanner.Bytes())
				if err != nil {
					return err
				}
				if match {
					level.Debug(logger).Log("msg", fmt.Sprintf("regex: %s matched: %s", qr.expect, scanner.Text()))
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
		if len(qr.expectBytes) > 0 {
			buffer := make([]byte, len(qr.expectBytes))
			_, err = io.ReadFull(conn, buffer)
			if err != nil {
				return nil
			}
			level.Debug(logger).Log("msg", fmt.Sprintf("read bytes: %x", buffer))
			if bytes.Compare(buffer, qr.expectBytes) != 0 {
				return fmt.Errorf("read bytes %x didn't match with expected bytes %x", buffer, qr.expectBytes)
			} else {
				level.Debug(logger).Log("msg", fmt.Sprintf("expected bytes %x matched with read bytes %x", qr.expectBytes, buffer))
			}
		}
		if qr.send != "" {
			level.Debug(logger).Log("msg", fmt.Sprintf("sending line: %s", qr.send))
			if _, err := fmt.Fprintf(conn, "%s\r\n", qr.send); err != nil {
				return err
			}
		}
		if len(qr.sendBytes) > 0 {
			level.Debug(logger).Log("msg", fmt.Sprintf("sending bytes: %x", qr.sendBytes))
			if _, err = conn.Write(qr.sendBytes); err != nil {
				return err
			}
		}
	}
	return nil
}
