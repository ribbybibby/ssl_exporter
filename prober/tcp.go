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
	expectFn    func(buffer []byte, bytes int) error
}

var (
	// BUFFSIZE is default size in bytes for generic buffer
	BUFFSIZE = 8 * 1024
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
		"mysql": []queryResponse{
			queryResponse{
				expectFn: func(buffer []byte, bytes int) error {
					if bytes == 0 {
						return fmt.Errorf("read 0 bytes from MySQL server")
					} else if bytes < 21 {
						// Packet length[3], Packet number[1] + minimum payload[17]
						return fmt.Errorf("MySQL packet too short. Expected length > 21, got %d", bytes)
					} else if bytes != (4 + int(buffer[0]) + (int(buffer[1]) << 8) + (int(buffer[2]) << 16)) {
						// Packet length[3], Packet number[1] + minimum payload[17]
						return fmt.Errorf(
							"MySQL packet length does not match. Got %d, expected %d",
							bytes,
							4+int(buffer[0])+(int(buffer[1])<<8)+(int(buffer[2])<<16),
						)
					} else if buffer[4] != 0xA {
						// protocol version[1]
						return fmt.Errorf("Only MySQL protocol version 10 (0xA) is supported. Got %x", buffer[4])
					}
					position := 5
					// server version[string+NULL]
					for ; ; position++ {
						if position >= bytes {
							return fmt.Errorf("Cannot confirm MySQL version")
						} else if buffer[position] == 0 {
							break
						}
					}
					position++
					// make sure we have at least 15 bytes left in the packet
					if position+15 > bytes {
						return fmt.Errorf("MySQL server handshake packet is broken")
					}

					position += 12             // skip over conn id[4] + SALT[8]
					if buffer[position] != 0 { // verify filler
						return fmt.Errorf(
							"MySQL packet is broken. Expected null at %d position, got %x",
							position,
							buffer[position],
						)
					}
					position++

					// capability flags[2]
					// !((packet[pos] + (packet[pos + 1] << 8)) & ssl_flg)
					if (int(buffer[position]) + (int(buffer[position+1])<<8)&0x800) == 0 {
						return fmt.Errorf("MySQL server does not support SSL")
					}
					return nil
				},
			},
			queryResponse{
				sendBytes: []byte{
					/* payload_length,   sequence_id */
					0x20, 0x00, 0x00, 0x01,
					/* payload */
					/* capability flags, CLIENT_SSL always set */
					0x85, 0xae, 0x7f, 0x00,
					/* max-packet size */
					0x00, 0x00, 0x00, 0x01,
					/* character set */
					0x21,
					/* string[23] reserved (all [0]) */
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
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

	actions, ok := startTLSqueryResponses[proto]
	if !ok {
		return fmt.Errorf("STARTTLS is not supported for %s", proto)
	}

	scanner := bufio.NewScanner(conn)
	for _, qr := range actions {
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
			if len(qr.expectBytes) > 0 {
				if bytes.Compare(buffer, qr.expectBytes) != 0 {
					return fmt.Errorf("read bytes %x didn't match with expected bytes %x", buffer, qr.expectBytes)
				}
				level.Debug(logger).Log("msg", fmt.Sprintf("expected bytes %x matched with read bytes %x", qr.expectBytes, buffer))
			}
		}
		if qr.expectFn != nil {
			buffer := make([]byte, BUFFSIZE)
			bytes, err := conn.Read(buffer)
			if err != nil {
				return nil
			}
			level.Debug(logger).Log("msg", fmt.Sprintf("read bytes: %x", buffer))

			if err := qr.expectFn(buffer, bytes); err != nil {
				return err
			}
			level.Debug(logger).Log("msg", fmt.Sprintf("expected function for %s matched with read bytes %x", proto, buffer))
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
