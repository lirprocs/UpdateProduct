package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CertGenerator struct {
	caCert  *x509.Certificate
	caKey   *rsa.PrivateKey
	certDir string
	keyDir  string
}

func NewCertGenerator(certDir, keyDir string) *CertGenerator {
	return &CertGenerator{
		certDir: certDir,
		keyDir:  keyDir,
	}
}

func (cg *CertGenerator) GenerateCA() error {
	fmt.Println("We are generating a root CA certificate...")

	os.MkdirAll(cg.certDir, 0755)
	os.MkdirAll(cg.keyDir, 0755)

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("CA key generation error: %v", err)
	}
	cg.caKey = caKey

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"BadSSL Test CA"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         "BadSSL Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("error creating the CA certificate: %v", err)
	}

	cg.caCert, err = x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("certificate CA parsing error: %v", err)
	}

	if err := cg.saveCert("ca-root.crt", caCertDER); err != nil {
		return err
	}

	if err := cg.saveKey("ca-root.key", caKey); err != nil {
		return err
	}

	fmt.Println("The root CA certificate has been created")
	return nil
}

func (cg *CertGenerator) GenerateWildcardCert() error {
	fmt.Println("Generating a wildcard certificate...")

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("certificate key generation error: %v", err)
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"BadSSL Test"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(2, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost", "*.badssl.test", "badssl.test", "self-signed.badssl.test", "expired.badssl.test", "mixed.badssl.test", "rc4.badssl.test", "hsts.badssl.test"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, cg.caCert, &certKey.PublicKey, cg.caKey)
	if err != nil {
		return fmt.Errorf("certificate creation error: %v", err)
	}

	if err := cg.saveCert("wildcard.crt", certDER); err != nil {
		return err
	}

	if err := cg.saveKey("wildcard.key", certKey); err != nil {
		return err
	}

	fmt.Println("Wildcard certificate has been created")
	return nil
}

func (cg *CertGenerator) saveCert(filename string, certDER []byte) error {
	certFile, err := os.Create(cg.certDir + "/" + filename)
	if err != nil {
		return fmt.Errorf("certificate file creation error: %v", err)
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func (cg *CertGenerator) saveKey(filename string, key *rsa.PrivateKey) error {
	keyFile, err := os.Create(cg.keyDir + "/" + filename)
	if err != nil {
		return fmt.Errorf("key file creation error: %v", err)
	}
	defer keyFile.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	return pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
}

func (cg *CertGenerator) GenerateAllCerts() error {
	fmt.Println("Generate all certificates for badssl.com...")

	if err := cg.GenerateCA(); err != nil {
		return err
	}

	if err := cg.GenerateWildcardCert(); err != nil {
		return err
	}
	return nil
}

func (cg *CertGenerator) saveCRL(filename string, crlDER []byte) error {
	if err := os.MkdirAll(cg.certDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(cg.certDir, filename))
	if err != nil {
		return err
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	}); err != nil {
		return err
	}

	return nil
}
