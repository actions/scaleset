package scaleset

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCertificates is a freshly generated TLS fixture set: a root CA, a
// server certificate signed directly by it, and a server certificate
// presenting a chain through an intermediate CA. Everything is generated
// in memory per test, so there is nothing to commit and nothing to expire.
type testCertificates struct {
	rootCA      *x509.Certificate
	server      tls.Certificate
	serverChain tls.Certificate
}

func generateTestCertificates(t *testing.T) testCertificates {
	t.Helper()

	now := time.Now()
	var serial int64
	issue := func(commonName string, isCA bool, issuer *tls.Certificate) tls.Certificate {
		serial++
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: commonName},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			IsCA:                  isCA,
			BasicConstraintsValid: true,
		}
		if isCA {
			template.KeyUsage = x509.KeyUsageCertSign
		} else {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}

		parent, signer := template, any(key)
		if issuer != nil {
			parent, signer = issuer.Leaf, issuer.PrivateKey
		}

		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatalf("creating certificate %q: %v", commonName, err)
		}

		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing certificate %q: %v", commonName, err)
		}

		return tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        leaf,
		}
	}

	root := issue("Test Root CA", true, nil)
	intermediate := issue("Test Intermediate CA", true, &root)
	server := issue("localhost", false, &root)
	serverChain := issue("localhost", false, &intermediate)
	serverChain.Certificate = append(serverChain.Certificate, intermediate.Certificate[0])

	return testCertificates{
		rootCA:      root.Leaf,
		server:      server,
		serverChain: serverChain,
	}
}

func writeTestKeyPair(t *testing.T, cert tls.Certificate) (string, string) {
	t.Helper()
	dir := t.TempDir()

	writePEM := func(name, blockType string, der []byte) string {
		path := filepath.Join(dir, name)
		data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return path
	}

	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}

	return writePEM("cert.pem", "CERTIFICATE", cert.Certificate[0]),
		writePEM("key.pem", "PRIVATE KEY", key)
}
