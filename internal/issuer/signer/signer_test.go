package signer

import (
	"context"
	"testing"

	essendixcissuerapi "github.com/angeloxx/cert-manager-essendi-xc-issuer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestEssendixcSigner(t *testing.T) {
	issuer := &essendixcissuerapi.IssuerSpec{
		URL:            "http://localhost",
		ProfileName:    "test",
		SubscriberName: "test",
	}
	secret := map[string][]byte{
		"client-id":     []byte("test"),
		"client-secret": []byte("test"),
		"token":         []byte("test"),
		"signature-key": []byte("test"),
	}

	signer, err := EssendiSignerFromIssuerAndSecretData(context.Background(), issuer, "test", secret)
	assert.NoError(t, err)

	t.Run("Test GetRefreshToken", func(t *testing.T) {
		_, err := signer.GetRefreshToken()
		assert.NoError(t, err)
	})

	t.Run("Test SubmitCertificateRequest", func(t *testing.T) {
		_, err := signer.SubmitCertificateRequest("test", []byte("test"))
		assert.NoError(t, err)
	})

	t.Run("Test RequestTaskStatus", func(t *testing.T) {
		_, _, err := signer.RequestTaskStatus("test", "test")
		assert.NoError(t, err)
	})

	t.Run("Test FetchCertificate", func(t *testing.T) {
		_, err := signer.FetchCertificate("test", "test")
		assert.NoError(t, err)
	})
}
