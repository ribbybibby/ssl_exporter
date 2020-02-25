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
MIIC6jCCApCgAwIBAgIQPbn1oJJ0lvHOxk3BbnhGMTAKBggqhkjOPQQDAjCBhTEL
MAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxvbmRvbjEU
MBIGA1UECRMLMTIzIEZha2UgU3QxEDAOBgNVBBETB1NXMThYWFgxEzARBgNVBAoT
CnJpYmJ5YmliYnkxFjAUBgNVBAMTDXJpYmJ5YmliYnkubWUwHhcNMTkwMzI5MDc1
MjI5WhcNMjAwMzI4MDc1MjI5WjAdMRswGQYDVQQDExJjZXJ0LnJpYmJ5YmliYnku
bWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASlHGGsAAEMpyBVkgSZazMcYmHH
4K8+m9VI9nSnD4t1b01jYuNAsJjvnRI2iGLOxQ1i8KgzgeZz6ud1mJLIudTzo4IB
RzCCAUMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAMBgNVHRMBAf8EAjAAMGgGA1UdDgRhBF9mNzphMzo4NDo0ZDo0NjowOTpl
Nzo5ZDpiNzo3MjphMTo5ZTpkOTpjMDoxYTpmYzpjMzplODplZDozOTozMTo5Mzox
MjpmMDplZTowODo2YTo2Mzo3NzphNjplMDoyMjBqBgNVHSMEYzBhgF8xNTpkZDo0
MTo4ODoxODo0YjoxOTo2NToyYjo2ZTo0Njo1NTozZTo3MTo0MzpjYjphMjo3Nzpk
YzpiNTpjZToxMTpiZTo2NDo3ODo3Zjo1OTo2NzpiYTpmMDo0YTowNTAuBgNVHREE
JzAlghJjZXJ0LnJpYmJ5YmliYnkubWWCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjO
PQQDAgNIADBFAiEAq5AUjiAQxMy0g0f2KyFshTu5QPXXSPo+VTBSQcYuEzICIAWr
JxpZXB4hH2+sEZ4z+bH6l47wbYqOT02d/VNbk3vw
-----END CERTIFICATE-----`

var clientKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPfP8yJatMwUfCyNdIQiQANO2vd3QQIoHJ6g+o8kb7PJoAoGCCqGSM49
AwEHoUQDQgAEpRxhrAABDKcgVZIEmWszHGJhx+CvPpvVSPZ0pw+LdW9NY2LjQLCY
750SNohizsUNYvCoM4Hmc+rndZiSyLnU8w==
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
MIIC6jCCApGgAwIBAgIRAO+sgyd/vcnDgfmafkgALKwwCgYIKoZIzj0EAwIwgYUx
CzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25kb24x
FDASBgNVBAkTCzEyMyBGYWtlIFN0MRAwDgYDVQQREwdTVzE4WFhYMRMwEQYDVQQK
EwpyaWJieWJpYmJ5MRYwFAYDVQQDEw1yaWJieWJpYmJ5Lm1lMB4XDTE5MDMyOTA3
NTIyN1oXDTIwMDMyODA3NTIyN1owHTEbMBkGA1UEAxMSY2VydC5yaWJieWJpYmJ5
Lm1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY5nQFSmpZnFvjbAicuElYlT2
xQvO+LgYt+5bcGfemT5HRq63tljiGlsyNXAysAmMwT9+blu8sLqkyh6PMFesJ6OC
AUcwggFDMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwDAYDVR0TAQH/BAIwADBoBgNVHQ4EYQRfZmI6NDM6NWY6M2Y6NTE6NGI6
NjA6YTI6YzQ6NzI6ZjE6MGQ6OTM6ZDA6YjQ6ODA6N2Y6Mjc6NjM6Yjk6NWI6NTQ6
ZGQ6NzI6NzU6N2Q6MDU6N2U6ZTc6Y2U6OTM6YTMwagYDVR0jBGMwYYBfMTU6ZGQ6
NDE6ODg6MTg6NGI6MTk6NjU6MmI6NmU6NDY6NTU6M2U6NzE6NDM6Y2I6YTI6Nzc6
ZGM6YjU6Y2U6MTE6YmU6NjQ6Nzg6N2Y6NTk6Njc6YmE6ZjA6NGE6MDUwLgYDVR0R
BCcwJYISY2VydC5yaWJieWJpYmJ5Lm1lgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDRwAwRAIgI6w7Px0UnI3AAP4n9ApO1gNIhY+ECEb0EZvKopmNUn0CIHN4
MEaXLzEfNdNi7E521qIR+bhV/mu8nubZIsG4K383
-----END CERTIFICATE-----`

var serverKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAeLgH2jonGdCgdG1MpEy9wAgxvCSC4N7sK3hC0GZM7MoAoGCCqGSM49
AwEHoUQDQgAEY5nQFSmpZnFvjbAicuElYlT2xQvO+LgYt+5bcGfemT5HRq63tlji
GlsyNXAysAmMwT9+blu8sLqkyh6PMFesJw==
-----END EC PRIVATE KEY-----`

var expiredCert = `-----BEGIN CERTIFICATE-----
MIIC2DCCAn6gAwIBAgIQeP4wyiBMCZ5TLpM40Ho6UzAKBggqhkjOPQQDAjCBhTEL
MAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxvbmRvbjEU
MBIGA1UECRMLMTIzIEZha2UgU3QxEDAOBgNVBBETB1NXMThYWFgxEzARBgNVBAoT
CnJpYmJ5YmliYnkxFjAUBgNVBAMTDXJpYmJ5YmliYnkubWUwHhcNMTkwMzI5MDgw
MTM4WhcNMTkwMzI4MDgwMTM4WjAdMRswGQYDVQQDExJjZXJ0LnJpYmJ5YmliYnku
bWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASjDs0ehi0miAKmDnuCmRyWaKOY
+h0MugoFngChyygYCY+mOb/+HV5AYUEf1NFJLz4DtYnNKyWNHnX7vUPEh+Ico4IB
NTCCATEwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAMBgNVHRMBAf8EAjAAMGgGA1UdDgRhBF9mNTo1NDpmYzphNTo1ZjplMzo5
YTo3MzplNzo1YTo0ZDowNzo0MTo4YjoyOTo2ZDpiNzpiNTpjMDpiZjowMzpkZTo5
Zjo5NTozNzphMjphNDo4MDo2YTo3MDozNDpmNjBqBgNVHSMEYzBhgF9iOTpjMDo2
NzoyYjo2YTpiNzowMToyMjo2Zjo1NTplMjpiMDphNDoyNDo1YTo5NzplMzpjYzpi
MTo3Yjo4ZjoyNDpiNTo1NToxYzpiMDo3NTozMDplNToxZDo3OTpmZDAcBgNVHREE
FTATggCCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjOPQQDAgNIADBFAiB+ZGtScM5Y
QHra5d+lqFRJOd7WXkoU03QHWOP3pSqbCAIhAJreqVQ3dUME4j9LYbQWmD96agdL
2uxG31qfCa/T5TCq
-----END CERTIFICATE-----`

var expiredKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFDlw65IF8NLdgIWU1ipkMffcE6MgZ5DHTGzf0WN09EJoAoGCCqGSM49
AwEHoUQDQgAEow7NHoYtJogCpg57gpkclmijmPodDLoKBZ4AocsoGAmPpjm//h1e
QGFBH9TRSS8+A7WJzSsljR51+71DxIfiHA==
-----END EC PRIVATE KEY-----`

var caCert = `-----BEGIN CERTIFICATE-----
MIIDBjCCAqygAwIBAgIRAJxzFmvhp8ef68W7SQrt5KwwCgYIKoZIzj0EAwIwgYUx
CzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25kb24x
FDASBgNVBAkTCzEyMyBGYWtlIFN0MRAwDgYDVQQREwdTVzE4WFhYMRMwEQYDVQQK
EwpyaWJieWJpYmJ5MRYwFAYDVQQDEw1yaWJieWJpYmJ5Lm1lMB4XDTE5MDMyOTA3
NTIyMloXDTI0MDMyNzA3NTIyMlowgYUxCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdF
bmdsYW5kMQ8wDQYDVQQHEwZMb25kb24xFDASBgNVBAkTCzEyMyBGYWtlIFN0MRAw
DgYDVQQREwdTVzE4WFhYMRMwEQYDVQQKEwpyaWJieWJpYmJ5MRYwFAYDVQQDEw1y
aWJieWJpYmJ5Lm1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE94APL4adMA7A
tSSfxcHzzxdVBCwJju6jVCf5qRqG4Qz0neXlde6jIXocZvoboZJiA2e7BadnjoPN
2sTB8mgg4KOB+jCB9zAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zBo
BgNVHQ4EYQRfMTU6ZGQ6NDE6ODg6MTg6NGI6MTk6NjU6MmI6NmU6NDY6NTU6M2U6
NzE6NDM6Y2I6YTI6Nzc6ZGM6YjU6Y2U6MTE6YmU6NjQ6Nzg6N2Y6NTk6Njc6YmE6
ZjA6NGE6MDUwagYDVR0jBGMwYYBfMTU6ZGQ6NDE6ODg6MTg6NGI6MTk6NjU6MmI6
NmU6NDY6NTU6M2U6NzE6NDM6Y2I6YTI6Nzc6ZGM6YjU6Y2U6MTE6YmU6NjQ6Nzg6
N2Y6NTk6Njc6YmE6ZjA6NGE6MDUwCgYIKoZIzj0EAwIDSAAwRQIhANycTcKTH1DU
eu3Xuz8CdtgT67yqUTxDy0O5kS8fFPUVAiAV0u1M7dQYV+buY8oOLYnZxondrb7/
BNltD7A8Y0S0hw==
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

	ok := strings.Contains(rr.Body.String(), "ssl_cert_not_after{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me\",ou=\"\",serial_no=\"318581226177353336430613662595136105644\"} 1.585381947e+09")
	if !ok {
		t.Errorf("expected `ssl_cert_not_after{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me\",ou=\"\",serial_no=\"318581226177353336430613662595136105644\"} 1.585381947e+09`")
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

	ok := strings.Contains(rr.Body.String(), "ssl_cert_not_before{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me\",ou=\"\",serial_no=\"318581226177353336430613662595136105644\"} 1.553845947e+09")
	if !ok {
		t.Errorf("expected `ssl_cert_not_before{cn=\"cert.ribbybibby.me\",dnsnames=\",cert.ribbybibby.me,localhost,\",emails=\"\",ips=\",127.0.0.1,\",issuer_cn=\"ribbybibby.me\",ou=\"\",serial_no=\"318581226177353336430613662595136105644\"} 1.553845947e+09`")
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

func certPool() *x509.CertPool {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(caCert))
	return certPool
}
