package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var clientCert = `-----BEGIN CERTIFICATE-----
MIIDCDCCAq6gAwIBAgIQN5eQ4E1ZLhVYNLKpa9UKTDAKBggqhkjOPQQDAjCBrTEL
MAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxvbmRvbjEU
MBIGA1UECRMLMTIzIEZha2UgU3QxEDAOBgNVBBETB1NXMThYWFgxEzARBgNVBAoT
CnJpYmJ5YmliYnkxPjA8BgNVBAMTNXJpYmJ5YmliYnkubWUgMTQyMDAxMTY5MjE2
MDAwNzEzOTA1OTI5OTY0NDU5MTU4NDkwNTE2MB4XDTIwMDUxODIwNTAxNloXDTMw
MDUxODIwNTAxNlowGDEWMBQGA1UEAxMNcmliYnliaWJieS5tZTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABC7JvrX2I31YWrg4pkFnGcHxXvAZhQGksYYdj/mlu9P2
8fqeALEkSmuntU8phYohcMDaQ8YQXWnmjKc8b6BzZ4GjggFCMIIBPjAOBgNVHQ8B
Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB
/wQCMAAwaAYDVR0OBGEEXzYxOmIxOjAzOjg2OjJiOjU1OmI1OjVkOmE4OmRlOmU1
OmI5OmRhOjNhOjA0OjRhOjBlOjc5OjYwOjE4OmYwOmEzOmIxOjczOjk1Ojk2OmYy
OmZjOjQ5OmYzOjcwOmUxMGoGA1UdIwRjMGGAXzhkOjY0OmNhOjI3OjdmOjlhOjQ0
OjMwOjYxOmE2OmUyOjYzOmU2OmNlOmNiOjVlOmY5Ojk2Ojg3OjM0OjZmOjRkOjQz
OmIzOjljOjEwOmM1OmJkOmMzOmQ0OmYxOjU3MCkGA1UdEQQiMCCCDXJpYmJ5Ymli
YnkubWWCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjOPQQDAgNIADBFAiEA69/tVE7u
fXMEOFHfqdPnp0uQ5dZlA7PMUUgm5QwwYgMCIBNwo/NinIHKRh1ocPGUDIQqcXTS
o6/eBbMK/8c0fgEX
-----END CERTIFICATE-----`

var clientKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF+A1wzrnIc2lwPLvygm+PXnrllB+tIxg8assCf3RP4zoAoGCCqGSM49
AwEHoUQDQgAELsm+tfYjfVhauDimQWcZwfFe8BmFAaSxhh2P+aW70/bx+p4AsSRK
a6e1TymFiiFwwNpDxhBdaeaMpzxvoHNngQ==
-----END EC PRIVATE KEY-----`

var clientCertWrong = `-----BEGIN CERTIFICATE-----
MIIC7zCCApWgAwIBAgIRAPx4XNhgs5QfvE6FHnYa3uQwCgYIKoZIzj0EAwIwgYUx
CzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25kb24x
FDASBgNVBAkTCzEyMyBGYWtlIFN0MRAwDgYDVQQREwdTVzE4WFhYMRMwEQYDVQQK
EwpyaWJieWJpYmJ5MRYwFAYDVQQDEw1yaWJieWJpYmJ5Lm1lMB4XDTE5MDMyNzE2
MTgzOVoXDTIwMDMyNjE2MTgzOVowHzEdMBsGA1UEAxMUY2xpZW50LnJpYmJ5Ymli
YnkubWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQtlqtCTzZNCdDiMHKD/p1F
97/I1MnkRK+QdUxEDnRhHAuMOhypxJ6NruZz+wXLnJEmUYmTsHkz1a4tKz2YJCUp
o4IBSTCCAUUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMGgGA1UdDgRhBF9kYzowNDozMjo0ZTpkOTo4
YjphNTplMDpmNjo5MjpkYzpiYzoxOTo1NTo0ZDo0YjpiNTo5YTo5OTpjYjo4Zjoz
ZjplMTpkNzo3MDoyMTo2MzpmZDo4YTo4MDpjMzpiNzBqBgNVHSMEYzBhgF82YTo0
MDozNTowZjpmZTowMjpkNzo0Zjo5ODozZTo3ODoyMTpjMDo0YTo5YzpjZTo2Nzoz
NDpiZDo4MjowYTo3MjpkMzpjOTo3Njo5MDo3Nzo5ODpmMDo2NTpmYzpkMDAwBgNV
HREEKTAnghRjbGllbnQucmliYnliaWJieS5tZYIJbG9jYWxob3N0hwR/AAABMAoG
CCqGSM49BAMCA0gAMEUCIQCa7ru0f0/HVoGa7aBJqACMBfiXWCI159WGt2B7Mxvf
VAIgX9O8fOl6qmsJyfMkfdmv6lo9oAWIecDLpVtqEj5i2Qc=
-----END CERTIFICATE-----`

var clientKeyWrong = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILnEJttULi+2cupO4ta6IB9bEeul6rMGFSpPMB7kPuSwoAoGCCqGSM49
AwEHoUQDQgAELZarQk82TQnQ4jByg/6dRfe/yNTJ5ESvkHVMRA50YRwLjDocqcSe
ja7mc/sFy5yRJlGJk7B5M9WuLSs9mCQlKQ==
-----END EC PRIVATE KEY-----`

var serverCert = `-----BEGIN CERTIFICATE-----
MIIDEjCCArigAwIBAgIQAWiOjpwbqjCd2VLhqfBs9DAKBggqhkjOPQQDAjCBrTEL
MAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxvbmRvbjEU
MBIGA1UECRMLMTIzIEZha2UgU3QxEDAOBgNVBBETB1NXMThYWFgxEzARBgNVBAoT
CnJpYmJ5YmliYnkxPjA8BgNVBAMTNXJpYmJ5YmliYnkubWUgMTQyMDAxMTY5MjE2
MDAwNzEzOTA1OTI5OTY0NDU5MTU4NDkwNTE2MB4XDTIwMDUxODIwNTczMVoXDTMw
MDUxODIwNTczMVowHTEbMBkGA1UEAxMSY2VydC5yaWJieWJpYmJ5Lm1lMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEuCd6wjji3seyDgOFqNNSSCdZ7RaJPGx9ra33
4wThFCF/kgMsK4yBpKSZoeHhFKN0dmuCfjMnX8Ubb6wS07coXaOCAUcwggFDMA4G
A1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYD
VR0TAQH/BAIwADBoBgNVHQ4EYQRfMDE6MTA6ZTY6NmY6MjE6Yzk6ZGQ6Zjc6NzI6
ZjI6MWE6ODc6OWY6NWI6MmU6Yjg6MGU6MWM6MmU6ZTc6NmI6YmI6NjU6ODU6ZTM6
NDA6M2Q6YzE6NjU6ZWM6MjM6YzMwagYDVR0jBGMwYYBfOGQ6NjQ6Y2E6Mjc6N2Y6
OWE6NDQ6MzA6NjE6YTY6ZTI6NjM6ZTY6Y2U6Y2I6NWU6Zjk6OTY6ODc6MzQ6NmY6
NGQ6NDM6YjM6OWM6MTA6YzU6YmQ6YzM6ZDQ6ZjE6NTcwLgYDVR0RBCcwJYISY2Vy
dC5yaWJieWJpYmJ5Lm1lgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZIzj0EAwIDSAAw
RQIgabP2m+FWJEdDWvTKn7usOEE5C4WQOChiRstnwyFK3SwCIQDx+aZeh1Kn055j
Tld1h2pxf6mUIpt82bHMqBLDGIMvkQ==
-----END CERTIFICATE-----`

var serverKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDV0ph/bjWman3fBUkandWMwbEZHxjmpO5CInT/GNFK8oAoGCCqGSM49
AwEHoUQDQgAEuCd6wjji3seyDgOFqNNSSCdZ7RaJPGx9ra334wThFCF/kgMsK4yB
pKSZoeHhFKN0dmuCfjMnX8Ubb6wS07coXQ==
-----END EC PRIVATE KEY-----`

var expiredCert = `-----BEGIN CERTIFICATE-----
MIIDCTCCAq+gAwIBAgIRAIA3Z/sLA7cEEJXVmhM8pO0wCgYIKoZIzj0EAwIwga0x
CzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25kb24x
FDASBgNVBAkTCzEyMyBGYWtlIFN0MRAwDgYDVQQREwdTVzE4WFhYMRMwEQYDVQQK
EwpyaWJieWJpYmJ5MT4wPAYDVQQDEzVyaWJieWJpYmJ5Lm1lIDE0MjAwMTE2OTIx
NjAwMDcxMzkwNTkyOTk2NDQ1OTE1ODQ5MDUxNjAeFw0yMDA1MTgyMDUyMTRaFw0y
MDA1MTgyMDUyMTRaMBgxFjAUBgNVBAMTDXJpYmJ5YmliYnkubWUwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASWQhdwCIVO7vA6kR4YqlFUWUhbuB7wuG3X0F+TIf/N
udXQCUSeEaYvhGd0O9Eoipu8FFxADtBPtLyzEi+/Rb5oo4IBQjCCAT4wDgYDVR0P
AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMB
Af8EAjAAMGgGA1UdDgRhBF84ODphNzozNDo3Yzo2Mjo5YTpiNDo0MjoyMTo2NDph
NTo1NDowMDowMjpmYToyODo1MTo5Zjo5Yjo0ZjpkYTphNzo0ZDplNDphNTpmYTpj
Mjo4MTpiNjphOTphZTo2YzBqBgNVHSMEYzBhgF84ZDo2NDpjYToyNzo3Zjo5YTo0
NDozMDo2MTphNjplMjo2MzplNjpjZTpjYjo1ZTpmOTo5Njo4NzozNDo2Zjo0ZDo0
MzpiMzo5YzoxMDpjNTpiZDpjMzpkNDpmMTo1NzApBgNVHREEIjAggg1yaWJieWJp
YmJ5Lm1lgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZIzj0EAwIDSAAwRQIhAMOftgrZ
7IYp/GvGIzWtxqevCKS6Rx2DoRnE0vHBhz2OAiBA01HjZcqDe5MHNaroipD2UEvP
3UrT7Jt2CPU/cO29iA==
-----END CERTIFICATE-----`

var expiredKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEoRpq0nEZmeUyQfw3zPD41fIlpwhb0Pz124ySxcMd/LoAoGCCqGSM49
AwEHoUQDQgAElkIXcAiFTu7wOpEeGKpRVFlIW7ge8Lht19BfkyH/zbnV0AlEnhGm
L4RndDvRKIqbvBRcQA7QT7S8sxIvv0W+aA==
-----END EC PRIVATE KEY-----`

var caCert = `-----BEGIN CERTIFICATE-----
MIIDVDCCAvugAwIBAgIQatRuLj4pm27y05vlZgVNlDAKBggqhkjOPQQDAjCBrTEL
MAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxvbmRvbjEU
MBIGA1UECRMLMTIzIEZha2UgU3QxEDAOBgNVBBETB1NXMThYWFgxEzARBgNVBAoT
CnJpYmJ5YmliYnkxPjA8BgNVBAMTNXJpYmJ5YmliYnkubWUgMTQyMDAxMTY5MjE2
MDAwNzEzOTA1OTI5OTY0NDU5MTU4NDkwNTE2MB4XDTIwMDUxODIwNDY0M1oXDTMw
MDUxODIwNDY0M1owga0xCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8w
DQYDVQQHEwZMb25kb24xFDASBgNVBAkTCzEyMyBGYWtlIFN0MRAwDgYDVQQREwdT
VzE4WFhYMRMwEQYDVQQKEwpyaWJieWJpYmJ5MT4wPAYDVQQDEzVyaWJieWJpYmJ5
Lm1lIDE0MjAwMTE2OTIxNjAwMDcxMzkwNTkyOTk2NDQ1OTE1ODQ5MDUxNjBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABNaeIKFsLCEGiEKBkTas0o/0zs1qEEboelkJ
Zm/SV+v4yKzsmWg2ExW9lyuV2WInSq38LgWIqd8dYC2hdl2Z1tGjgfowgfcwDgYD
VR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8waAYDVR0OBGEEXzhkOjY0OmNh
OjI3OjdmOjlhOjQ0OjMwOjYxOmE2OmUyOjYzOmU2OmNlOmNiOjVlOmY5Ojk2Ojg3
OjM0OjZmOjRkOjQzOmIzOjljOjEwOmM1OmJkOmMzOmQ0OmYxOjU3MGoGA1UdIwRj
MGGAXzhkOjY0OmNhOjI3OjdmOjlhOjQ0OjMwOjYxOmE2OmUyOjYzOmU2OmNlOmNi
OjVlOmY5Ojk2Ojg3OjM0OjZmOjRkOjQzOmIzOjljOjEwOmM1OmJkOmMzOmQ0OmYx
OjU3MAoGCCqGSM49BAMCA0cAMEQCIGvh2F03SqFgBwAlTBVxPcdfaBYFxKEmHLOS
SKpwT6SNAiAo7lmkPE5GbwNCSbIsgzfYLkXoGFA+UPqxI99/SRffmA==
-----END CERTIFICATE-----`

// Test the basic case: a typical HTTPS server
func TestProbeHandlerConnectSuccess(t *testing.T) {
	server, err := server()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 1`")
	}

	server.Close()
}

// Test against a non-existent server
func TestProbeHandlerConnectSuccessFalse(t *testing.T) {
	rr, err := probe("localhost:6666")
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}

}

// Test with an empty target
func TestProbeHandlerEmptyTarget(t *testing.T) {
	rr, err := probe("")
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}

}

// Test with spaces in the target
func TestProbeHandlerSpaces(t *testing.T) {
	rr, err := probe("with spaces")
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

// Test with a uri protocol the exporter doesn't implement a client for
func TestProbeHandlerBadScheme(t *testing.T) {
	rr, err := probe("ldaps://example.com")
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}
}

// Test that probe uses a http client when the scheme is https://
func TestProbeHandlerHTTPSClient(t *testing.T) {
	rr, err := probe("https://example.com")
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_client_protocol{protocol=\"https\"} 1")
	if !ok {
		t.Errorf("expected `ssl_client_protocol{protocol=\"https\"} 1`")
	}

	ok = strings.Contains(rr.Body.String(), "ssl_client_protocol{protocol=\"tcp\"} 0")
	if !ok {
		t.Errorf("expected `ssl_client_protocol{protocol=\"tcp\"} 0`")
	}
}

// Test that probe uses a tcp client when the host is of the form <host>:<port>
func TestProbeHandlerTCPClient(t *testing.T) {
	rr, err := probe("example.com:443")
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_client_protocol{protocol=\"tcp\"} 1")
	if !ok {
		t.Errorf("expected `ssl_client_protocol{protocol=\"tcp\"} 1`")
	}

	ok = strings.Contains(rr.Body.String(), "ssl_client_protocol{protocol=\"https\"} 0")
	if !ok {
		t.Errorf("expected `ssl_client_protocol{protocol=\"https\"} 0`")
	}
}

// Test that a https client is used when there is no protocol or port in the target address
func TestProbeHandlerNoProtocolNoPort(t *testing.T) {
	rr, err := probe("example.com")
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_client_protocol{protocol=\"https\"} 1")
	if !ok {
		t.Errorf("expected `ssl_client_protocol{protocol=\"https\"} 1`")
	}
}

// Test against a HTTP server
func TestProbeHandlerHTTP(t *testing.T) {
	server, err := serverHTTP()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}

	server.Close()
}

// Test that the exporter returns the correct notAfter value
func TestProbeHandlerNotAfter(t *testing.T) {
	server, err := server()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_cert_not_after{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me 142001169216000713905929964459158490516\",ou=\"\",serial_no=\"1872118269948439737386560021043637492\"} 1.905368251e+09")
	if !ok {
		t.Errorf("expected `ssl_cert_not_after{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me 142001169216000713905929964459158490516\",ou=\"\",serial_no=\"1872118269948439737386560021043637492\"} 1.905368251e+09`")
	}

	server.Close()
}

// Test that the exporter returns the correct notBefore value
func TestProbeHandlerNotBefore(t *testing.T) {
	server, err := server()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_cert_not_before{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me 142001169216000713905929964459158490516\",ou=\"\",serial_no=\"1872118269948439737386560021043637492\"} 1.589835451e+09")
	if !ok {
		t.Errorf("expected `ssl_cert_not_before{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me 142001169216000713905929964459158490516\",ou=\"\",serial_no=\"1872118269948439737386560021043637492\"} 1.589835451e+09`")
	}

	server.Close()
}

// Test that the exporter returns the correct list of IPs
func TestProbeHandlerIPs(t *testing.T) {
	server, err := server()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ips=\",127.0.0.1,\"")
	if !ok {
		t.Errorf("expected `ips=\",127.0.0.1,\"`")
	}

	server.Close()
}

// Test that the exporter returns the correct CN
func TestProbeHandlerCommonName(t *testing.T) {
	server, err := server()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}
	log.Println(rr.Body.String())
	ok := strings.Contains(rr.Body.String(), "cn=\"cert.ribbybibby.me\"")
	if !ok {
		t.Errorf("expected `cn=\"cert.ribbybibby.me\"`")
	}

	server.Close()
}

// Test that the exporter returns the correct list of DNS names
func TestProbeHandlerDNSNames(t *testing.T) {
	server, err := server()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "dnsnames=\",cert.ribbybibby.me,localhost,\"")
	if !ok {
		t.Errorf("expected `dnsnames=\",cert.ribbybibby.me,localhost,\"`")
	}

	server.Close()
}

// Test client authentication
func TestProbeHandlerClientAuth(t *testing.T) {
	server, err := serverClientAuth()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probeClientAuth(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 1`")
	}

	server.Close()
}

// Test client authentication with a bad client certificate
func TestProbeHandlerClientAuthWrongClientCert(t *testing.T) {
	server, err := serverClientAuth()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probeClientAuthBad(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}

	server.Close()
}

// Test against a server with an expired certificate
func TestProbeHandlerExpired(t *testing.T) {
	server, err := serverExpired()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 0")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 0`")
	}

	server.Close()
}

// Test against a server with an expired certificate with an insecure probe
func TestProbeHandlerExpiredInsecure(t *testing.T) {
	server, err := serverExpired()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probeInsecure(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_connect_success 1")
	if !ok {
		t.Errorf("expected `ssl_tls_connect_success 1`")
	}

	server.Close()
}

// Test against a server with TLS v1.2
func TestProbeHandlerTLSVersion12(t *testing.T) {
	server, err := serverTLSVersion12()
	if err != nil {
		t.Fatalf(err.Error())
	}

	rr, err := probe(server.URL)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ok := strings.Contains(rr.Body.String(), "ssl_tls_version_info{version=\"TLS 1.2\"} 1")
	if !ok {
		t.Errorf("expected `ssl_tls_version_info{version=\"TLS 1.2\"} 1`")
	}

	server.Close()
}

func probe(url string) (*httptest.ResponseRecorder, error) {
	uri := "/probe?target=" + url
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, &tls.Config{
			RootCAs: certPool(),
		})
	})

	handler.ServeHTTP(rr, req)

	return rr, nil
}

func probeInsecure(url string) (*httptest.ResponseRecorder, error) {
	uri := "/probe?target=" + url
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, &tls.Config{
			RootCAs:            certPool(),
			InsecureSkipVerify: true,
		})
	})

	handler.ServeHTTP(rr, req)

	return rr, nil
}

func probeClientAuth(url string) (*httptest.ResponseRecorder, error) {
	clientCertificate, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
	if err != nil {
		return nil, err
	}

	uri := "/probe?target=" + url
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      certPool(),
		})
	})

	handler.ServeHTTP(rr, req)

	return rr, nil
}

func probeClientAuthBad(url string) (*httptest.ResponseRecorder, error) {
	clientCertificate, err := tls.X509KeyPair([]byte(clientCertWrong), []byte(clientKeyWrong))
	if err != nil {
		return nil, err
	}

	uri := "/probe?target=" + url
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      certPool(),
		})
	})

	handler.ServeHTTP(rr, req)

	return rr, nil
}

func server() (*httptest.Server, error) {
	serverCertificate, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		return nil, err
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
	}

	server.StartTLS()
	return server, nil
}

func serverClientAuth() (*httptest.Server, error) {
	certPool := certPool()

	serverCertificate, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		return nil, err
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      certPool,
		ClientCAs:    certPool,
	}

	server.StartTLS()
	return server, nil
}

func serverExpired() (*httptest.Server, error) {
	certPool := certPool()

	serverCertificate, err := tls.X509KeyPair([]byte(expiredCert), []byte(expiredKey))
	if err != nil {
		return nil, err
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		RootCAs:      certPool,
		ClientCAs:    certPool,
	}

	server.StartTLS()
	return server, nil
}

func serverHTTP() (*httptest.Server, error) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))

	server.Start()
	return server, nil
}

func serverTLSVersion12() (*httptest.Server, error) {
	serverCertificate, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		return nil, err
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world")
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	server.StartTLS()
	return server, nil
}

func certPool() *x509.CertPool {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(caCert))
	return certPool
}
