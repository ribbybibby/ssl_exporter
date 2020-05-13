package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

// GenerateTestCertificate generates a test certificate with the given expiry date
func GenerateTestCertificate(expiry time.Time) ([]byte, []byte) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error creating rsa key: %s", err))
	}
	publickey := &privatekey.PublicKey

	cert := x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1},
		SerialNumber:          big.NewInt(100),
		Subject: pkix.Name{
			CommonName:         "example.ribbybibby.me",
			Organization:       []string{"ribbybibby"},
			OrganizationalUnit: []string{"ribbybibbys org"},
		},
		EmailAddresses: []string{"me@ribbybibby.me", "example@ribbybibby.me"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:       []string{"example.ribbybibby.me", "example-2.ribbybibby.me", "example-3.ribbybibby.me"},
		NotBefore:      time.Now(),
		NotAfter:       expiry,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, publickey, privatekey)
	if err != nil {
		panic(fmt.Sprintf("Error signing test-certificate: %s", err))
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
	return pemCert, pemKey
}

// WriteFile writes some content to a temporary file
func WriteFile(filename string, contents []byte) (string, error) {
	tmpFile, err := ioutil.TempFile("", filename)
	if err != nil {
		return tmpFile.Name(), err
	}
	if _, err := tmpFile.Write(contents); err != nil {
		return tmpFile.Name(), err
	}
	if err := tmpFile.Close(); err != nil {
		return tmpFile.Name(), err
	}

	return tmpFile.Name(), nil
}
