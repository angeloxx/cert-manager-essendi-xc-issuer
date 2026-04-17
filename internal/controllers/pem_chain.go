package controllers

import (
	"crypto/x509"
	"encoding/pem"
)

// extractCAFromPEMBundle scans a PEM bundle and returns the root CA certificate,
// identified as the only certificate that is both marked as CA and self-signed.
// Returns nil if no root CA is found.
func extractCAFromPEMBundle(bundle []byte) []byte {
	var rest []byte
	for block, r := pem.Decode(bundle); block != nil; block, r = pem.Decode(rest) {
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			return pem.EncodeToMemory(block)
		}
	}
	return nil
}
