package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractCAFromPEMBundle(t *testing.T) {
	rootPEM, rootCert, rootKey := mustCreateRoot(t)
	intermediatePEM, intermediateCert, intermediateKey := mustCreateIntermediate(t, rootCert, rootKey)
	leafPEM := mustCreateLeaf(t, intermediateCert, intermediateKey)
	selfIssuedNotSelfSignedCAPEM := mustCreateSelfIssuedNotSelfSignedCA(t)

	tests := map[string]struct {
		bundle     []byte
		expectedCA []byte
	}{
		"returns root when present": {
			bundle:     append(append(leafPEM, intermediatePEM...), rootPEM...),
			expectedCA: rootPEM,
		},
		"returns nil when only intermediate CA exists": {
			bundle:     append(leafPEM, intermediatePEM...),
			expectedCA: nil,
		},
		"returns nil for leaf only": {
			bundle:     leafPEM,
			expectedCA: nil,
		},
		"ignores malformed prefix": {
			bundle:     append([]byte("not-a-pem\n"), append(leafPEM, rootPEM...)...),
			expectedCA: rootPEM,
		},
		"ignores self-issued but not self-signed CA": {
			bundle:     selfIssuedNotSelfSignedCAPEM,
			expectedCA: nil,
		},
		"returns nil for empty input": {
			bundle:     nil,
			expectedCA: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			actual := extractCAFromPEMBundle(tc.bundle)
			assert.Equal(t, tc.expectedCA, actual)
		})
	}
}

func mustCreateRoot(t *testing.T) ([]byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, key
}

func mustCreateIntermediate(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey) ([]byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, key
}

func mustCreateLeaf(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "test-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustCreateSelfIssuedNotSelfSignedCA(t *testing.T) []byte {
	t.Helper()
	_, parentCert, parentKey := mustCreateRoot(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               parentCert.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
