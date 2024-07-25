package test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// GenerateTestCertificate generates a test certificate with the given expiry date
func GenerateTestCertificate(expiry time.Time) ([]byte, []byte) {
	return GenerateTestCertificateWithCRLDP(expiry, "")
}

// GenerateTestCertificateWithCRLDP generates a test certificate which contains a CRL distribution point
func GenerateTestCertificateWithCRLDP(expiry time.Time, crlURL string) ([]byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error creating rsa key: %s", err))
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert := GenerateCertificateTemplate(expiry)
	cert.IsCA = true
	if crlURL != "" {
		cert.CRLDistributionPoints = []string{crlURL}
	}

	_, pemCert := GenerateSelfSignedCertificateWithPrivateKey(cert, privateKey)

	return pemCert, pemKey
}

// GenerateSignedCertificate generates a certificate that is signed
func GenerateSignedCertificate(cert, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, []byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error creating rsa key: %s", err))
	}

	derCert, err := x509.CreateCertificate(rand.Reader, cert, parentCert, &privateKey.PublicKey, parentKey)
	if err != nil {
		panic(fmt.Sprintf("Error signing test-certificate: %s", err))
	}

	genCert, err := x509.ParseCertificate(derCert)
	if err != nil {
		panic(fmt.Sprintf("Error parsing test-certificate: %s", err))
	}

	return genCert,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

// GenerateSelfSignedCertificateWithPrivateKey generates a self signed
// certificate with the given private key
func GenerateSelfSignedCertificateWithPrivateKey(cert *x509.Certificate, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	derCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(fmt.Sprintf("Error signing test-certificate: %s", err))
	}

	genCert, err := x509.ParseCertificate(derCert)
	if err != nil {
		panic(fmt.Sprintf("Error parsing test-certificate: %s", err))
	}

	return genCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
}

// GenerateCertificateTemplate generates the template used to issue test certificates
func GenerateCertificateTemplate(expiry time.Time) *x509.Certificate {
	return &x509.Certificate{
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1},
		SerialNumber:          big.NewInt(100),
		NotBefore:             time.Now(),
		NotAfter:              expiry,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		Subject: pkix.Name{
			CommonName:         "example.ribbybibby.me",
			Organization:       []string{"ribbybibby"},
			OrganizationalUnit: []string{"ribbybibbys org"},
		},
		EmailAddresses: []string{"me@ribbybibby.me", "example@ribbybibby.me"},
		DNSNames:       []string{"example.ribbybibby.me", "example-2.ribbybibby.me", "example-3.ribbybibby.me"},
	}
}

func GenerateRevocationListEntry(serial *big.Int, reason int) *x509.RevocationListEntry {
	return &x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
		ReasonCode:     reason,
	}
}

// GenerateCRL generates a Certificate Revocation List
func GenerateCRL(entry *x509.RevocationListEntry, issuer *x509.Certificate, key crypto.Signer, expiry time.Time) ([]byte, error) {
	template := &x509.RevocationList{
		SignatureAlgorithm:        issuer.SignatureAlgorithm,
		Issuer:                    issuer.Subject,
		ThisUpdate:                time.Now(),
		NextUpdate:                expiry,
		RevokedCertificateEntries: []x509.RevocationListEntry{},
		Number:                    big.NewInt(1),
	}
	if entry != nil {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, *entry)
	}
	return x509.CreateRevocationList(rand.Reader, template, issuer, key)
}

// WriteFile writes some content to a temporary file
func WriteFile(filename string, contents []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", filename)
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
