package teetls

import (
	"bytes"
	"crypto/x509/pkix"
	"testing"
)

func TestGenerateSM2CertificateWithEvidence(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, keyPEM, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("empty cert or key PEM")
	}

	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse cert PEM: %v", err)
	}

	// Locate CSV evidence extension
	var foundExt *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(OIDCSVEvidence) {
			foundExt = &cert.Extensions[i]
			break
		}
	}
	if foundExt == nil {
		t.Fatalf("csv evidence extension not found in certificate")
	}

	ev, err := DecodeCSVEvidence(foundExt.Value)
	if err != nil {
		t.Fatalf("decode evidence: %v", err)
	}

	// Check that UserData[0:32] matches SM3 of public key
	pubDigest := ComputePublicKeySM3(cert.RawSubjectPublicKeyInfo)
	if !bytes.Equal(ev.Report[128:160], pubDigest[:]) { // UserData offset in CSV report is 128
		t.Errorf("public key SM3 digest does not match report UserData")
	}
}

func TestGenerateSM2Certificate_NilProvider(t *testing.T) {
	_, _, err := GenerateSM2CertificateWithEvidence(nil)
	if err == nil {
		t.Errorf("expected error with nil provider, got nil")
	}
}

func TestParseCertificatePEM_InvalidData(t *testing.T) {
	_, err := ParseCertificatePEM([]byte("invalid pem data"))
	if err == nil {
		t.Errorf("expected error parsing invalid pem, got nil")
	}
}

func TestHygonHardwareProvider_MockPath(t *testing.T) {
	prov := NewHygonHardwareProvider("/non/existent/dev", "", "")
	if prov.GetMeasurementHex() != "" {
		t.Errorf("expected empty measurement hex on non-existent hardware")
	}
	var dummy [32]byte
	_, err := prov.GetEvidence(dummy)
	if err == nil {
		t.Errorf("expected error from non-existent hardware device")
	}
}
