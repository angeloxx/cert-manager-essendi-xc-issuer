package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	essendixcissuerapi "github.com/angeloxx/cert-manager-essendi-xc-issuer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEssendiSignerFromIssuerAndSecretData(t *testing.T) {
	tests := []struct {
		name        string
		issuer      *essendixcissuerapi.IssuerSpec
		authRealm   string
		secret      map[string][]byte
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid-secret",
			issuer: &essendixcissuerapi.IssuerSpec{
				URL:            "https://example.com",
				ProfileName:    "test-profile",
				SubscriberName: "test-subscriber",
			},
			authRealm: "test-realm",
			secret: map[string][]byte{
				"client-id":     []byte("test-client-id"),
				"client-secret": []byte("test-client-secret"),
				"token":         []byte("test-token"),
				"signature-key": []byte("test-signature-key"),
			},
			expectError: false,
		},
		{
			name: "missing-client-id",
			issuer: &essendixcissuerapi.IssuerSpec{
				URL: "https://example.com",
			},
			authRealm: "test-realm",
			secret: map[string][]byte{
				"client-secret": []byte("test-client-secret"),
				"token":         []byte("test-token"),
				"signature-key": []byte("test-signature-key"),
			},
			expectError: true,
			errorMsg:    "client-id not found in secret",
		},
		{
			name: "missing-client-secret",
			issuer: &essendixcissuerapi.IssuerSpec{
				URL: "https://example.com",
			},
			authRealm: "test-realm",
			secret: map[string][]byte{
				"client-id":     []byte("test-client-id"),
				"token":         []byte("test-token"),
				"signature-key": []byte("test-signature-key"),
			},
			expectError: true,
			errorMsg:    "client-secret not found in secret",
		},
		{
			name: "missing-token",
			issuer: &essendixcissuerapi.IssuerSpec{
				URL: "https://example.com",
			},
			authRealm: "test-realm",
			secret: map[string][]byte{
				"client-id":     []byte("test-client-id"),
				"client-secret": []byte("test-client-secret"),
				"signature-key": []byte("test-signature-key"),
			},
			expectError: true,
			errorMsg:    "token not found in secret",
		},
		{
			name: "missing-signature-key",
			issuer: &essendixcissuerapi.IssuerSpec{
				URL: "https://example.com",
			},
			authRealm: "test-realm",
			secret: map[string][]byte{
				"client-id":     []byte("test-client-id"),
				"client-secret": []byte("test-client-secret"),
				"token":         []byte("test-token"),
			},
			expectError: true,
			errorMsg:    "signature-key not found in secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := EssendiSignerFromIssuerAndSecretData(context.Background(), tt.issuer, tt.authRealm, tt.secret)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, signer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, signer)
				
				// Type assertion to check internal fields
				essendixcSigner, ok := signer.(*essendixcSigner)
				require.True(t, ok)
				assert.Equal(t, tt.issuer, essendixcSigner.issuer)
				assert.Equal(t, tt.authRealm, essendixcSigner.realm)
				assert.Equal(t, string(tt.secret["client-id"]), essendixcSigner.clientID)
				assert.Equal(t, string(tt.secret["client-secret"]), essendixcSigner.clientSecret)
				assert.Equal(t, string(tt.secret["token"]), essendixcSigner.token)
				assert.Equal(t, string(tt.secret["signature-key"]), essendixcSigner.signatureKey)
			}
		})
	}
}

func TestEssendiHealthCheckerFromIssuerAndSecretData(t *testing.T) {
	issuer := &essendixcissuerapi.IssuerSpec{
		URL: "https://example.com",
	}
	secret := map[string][]byte{
		"client-id": []byte("test"),
	}

	checker, err := EssendiHealthCheckerFromIssuerAndSecretData(issuer, secret)
	assert.NoError(t, err)
	assert.NotNil(t, checker)
	
	// Test the Check method
	err = checker.Check()
	assert.NoError(t, err)
}

func TestEssendixcSigner_GetRefreshToken(t *testing.T) {
	// Create a test server to mock the OAuth2 token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/protocol/openid-connect/token")
		
		// Return a mock token response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	issuer := &essendixcissuerapi.IssuerSpec{
		URL: server.URL,
	}
	
	signer := &essendixcSigner{
		ctx:          context.Background(),
		issuer:       issuer,
		clientID:     "test-client",
		clientSecret: "test-secret",
		token:        "test-refresh-token",
		realm:        "test-realm",
		signatureKey: "test-key",
	}

	token, err := signer.GetRefreshToken()
	assert.NoError(t, err)
	assert.Equal(t, "test-access-token", token)
}

func TestEssendixcSigner_GetRefreshToken_Error(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(`{"error":"invalid_grant"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	issuer := &essendixcissuerapi.IssuerSpec{
		URL: server.URL,
	}
	
	signer := &essendixcSigner{
		ctx:          context.Background(),
		issuer:       issuer,
		clientID:     "test-client",
		clientSecret: "test-secret",
		token:        "invalid-refresh-token",
		realm:        "test-realm",
		signatureKey: "test-key",
	}

	token, err := signer.GetRefreshToken()
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "500")
}

func TestEssendixcSigner_SubmitCertificateRequest(t *testing.T) {
	// Generate a valid CSR for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	require.NoError(t, err)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Create a test server to mock the certificate request submission
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		assert.NotEmpty(t, r.Header.Get("X-Timestamp"))
		assert.NotEmpty(t, r.Header.Get("X-Signature"))
		
		// Return a mock response with Location header (202 Accepted)
		w.Header().Set("Location", "/api/task/test-task-123")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	issuer := &essendixcissuerapi.IssuerSpec{
		URL:            server.URL,
		ProfileName:    "test-profile",
		SubscriberName: "test-subscriber",
	}
	
	signer := &essendixcSigner{
		ctx:          context.Background(),
		issuer:       issuer,
		clientID:     "test-client",
		clientSecret: "test-secret",
		token:        "test-token",
		realm:        "test-realm",
		signatureKey: "test-key",
	}

	taskURL, err := signer.SubmitCertificateRequest("test-access-token", csrPEM)
	assert.NoError(t, err)
	assert.Equal(t, "/api/task/test-task-123", taskURL)
}

func TestEssendixcSigner_SubmitCertificateRequest_InvalidCSR(t *testing.T) {
	issuer := &essendixcissuerapi.IssuerSpec{
		URL: "https://example.com",
	}
	
	signer := &essendixcSigner{
		ctx:    context.Background(),
		issuer: issuer,
	}

	// Test with invalid CSR data
	taskID, err := signer.SubmitCertificateRequest("test-token", []byte("invalid-csr"))
	assert.Error(t, err)
	assert.Empty(t, taskID)
	assert.Contains(t, err.Error(), "PEM block type must be CERTIFICATE REQUEST")
}

func TestEssendixcSigner_RequestTaskStatus(t *testing.T) {
	// Create a test server to mock the task status endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		assert.NotEmpty(t, r.Header.Get("X-Timestamp"))
		assert.NotEmpty(t, r.Header.Get("X-Signature"))
		
		// Return a mock response indicating task is ready (303 See Other)
		w.Header().Set("Location", "/api/certificate/cert-456")
		w.WriteHeader(http.StatusSeeOther)
		_, err := w.Write([]byte(`{"status":"ISSUED"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	issuer := &essendixcissuerapi.IssuerSpec{
		URL: server.URL,
	}
	
	signer := &essendixcSigner{
		ctx:    context.Background(),
		issuer: issuer,
	}

	certURL, status, err := signer.RequestTaskStatus("test-token", server.URL+"/api/task/task-123")
	assert.NoError(t, err)
	assert.Equal(t, "ISSUED", status)
	assert.Equal(t, "/api/certificate/cert-456", certURL)
}

func TestEssendixcSigner_RequestTaskStatus_NotReady(t *testing.T) {
	// Create a test server to mock the task status endpoint for pending task
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a response indicating task is still processing (200 OK)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"PROCESSING"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	issuer := &essendixcissuerapi.IssuerSpec{
		URL: server.URL,
	}
	
	signer := &essendixcSigner{
		ctx:    context.Background(),
		issuer: issuer,
	}

	certURL, status, err := signer.RequestTaskStatus("test-token", server.URL+"/api/task/task-123")
	assert.NoError(t, err)
	assert.Equal(t, "PROCESSING", status)
	assert.Empty(t, certURL)
}

func TestEssendixcSigner_FetchCertificate(t *testing.T) {
	// Create a test server to mock the certificate fetch endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		assert.NotEmpty(t, r.Header.Get("X-Timestamp"))
		assert.NotEmpty(t, r.Header.Get("X-Signature"))
		
		// Return a mock certificate in JSON format (200 OK)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"data":"-----BEGIN CERTIFICATE-----\ntest-certificate-data\n-----END CERTIFICATE-----"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	issuer := &essendixcissuerapi.IssuerSpec{
		URL: server.URL,
	}
	
	signer := &essendixcSigner{
		ctx:    context.Background(),
		issuer: issuer,
	}

	cert, err := signer.FetchCertificate("test-token", server.URL+"/api/certificate/cert-456")
	assert.NoError(t, err)
	assert.Contains(t, string(cert), "BEGIN CERTIFICATE")
	assert.Contains(t, string(cert), "test-certificate-data")
}

func TestEssendixcSigner_FetchCertificate_Error(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, err := w.Write([]byte(`{"description":"certificate not found"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	issuer := &essendixcissuerapi.IssuerSpec{
		URL: server.URL,
	}
	
	signer := &essendixcSigner{
		ctx:    context.Background(),
		issuer: issuer,
	}

	cert, err := signer.FetchCertificate("test-token", server.URL+"/api/certificate/invalid-cert-id")
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "certificate not found")
}
