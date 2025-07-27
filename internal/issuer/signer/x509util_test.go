package signer

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

func TestParseKey(t *testing.T) {
	// Generate a test RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Convert to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	tests := []struct {
		name        string
		pemBytes    []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid-rsa-private-key",
			pemBytes:    privateKeyPEM,
			expectError: false,
		},
		{
			name:        "invalid-pem-format",
			pemBytes:    []byte("not a pem file"),
			expectError: true,
			errorMsg:    "PEM block type must be RSA PRIVATE KEY",
		},
		{
			name: "wrong-pem-type",
			pemBytes: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("fake cert bytes"),
			}),
			expectError: true,
			errorMsg:    "PEM block type must be RSA PRIVATE KEY",
		},
		{
			name:        "empty-input",
			pemBytes:    []byte(""),
			expectError: true,
			errorMsg:    "PEM block type must be RSA PRIVATE KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseKey(tt.pemBytes)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
				assert.IsType(t, &rsa.PrivateKey{}, key)
				// Verify key properties
				assert.Equal(t, 2048, key.N.BitLen())
			}
		})
	}
}

func TestParseCert(t *testing.T) {
	// Generate a test certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	tests := []struct {
		name        string
		pemBytes    []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid-certificate",
			pemBytes:    certPEM,
			expectError: false,
		},
		{
			name:        "invalid-pem-format",
			pemBytes:    []byte("not a pem file"),
			expectError: true,
			errorMsg:    "PEM block type must be CERTIFICATE",
		},
		{
			name: "wrong-pem-type",
			pemBytes: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("fake key bytes"),
			}),
			expectError: true,
			errorMsg:    "PEM block type must be CERTIFICATE",
		},
		{
			name:        "empty-input",
			pemBytes:    []byte(""),
			expectError: true,
			errorMsg:    "PEM block type must be CERTIFICATE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCert(tt.pemBytes)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, cert)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cert)
				assert.IsType(t, &x509.Certificate{}, cert)
				// Verify certificate properties
				assert.Equal(t, "test.example.com", cert.Subject.CommonName)
			}
		})
	}
}

func TestParseCSR(t *testing.T) {
	// Generate a test CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	require.NoError(t, err)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	tests := []struct {
		name        string
		pemBytes    []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid-certificate-request",
			pemBytes:    csrPEM,
			expectError: false,
		},
		{
			name:        "invalid-pem-format",
			pemBytes:    []byte("not a pem file"),
			expectError: true,
			errorMsg:    "PEM block type must be CERTIFICATE REQUEST",
		},
		{
			name: "wrong-pem-type",
			pemBytes: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("fake cert bytes"),
			}),
			expectError: true,
			errorMsg:    "PEM block type must be CERTIFICATE REQUEST",
		},
		{
			name:        "empty-input",
			pemBytes:    []byte(""),
			expectError: true,
			errorMsg:    "PEM block type must be CERTIFICATE REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr, err := parseCSR(tt.pemBytes)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, csr)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, csr)
				assert.IsType(t, &x509.CertificateRequest{}, csr)
				// Verify CSR properties
				assert.Equal(t, "test.example.com", csr.Subject.CommonName)
				assert.Contains(t, csr.DNSNames, "test.example.com")
				assert.Contains(t, csr.DNSNames, "www.test.example.com")
			}
		})
	}
}

func TestParseCSR_VerifySignature(t *testing.T) {
	// Generate a test CSR and verify the signature
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "signature-test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	require.NoError(t, err)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	csr, err := parseCSR(csrPEM)
	require.NoError(t, err)

	// Verify the signature on the CSR
	err = csr.CheckSignature()
	assert.NoError(t, err, "CSR signature should be valid")
}