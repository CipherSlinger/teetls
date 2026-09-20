package teetls

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	gx509 "github.com/tjfoc/gmsm/x509"
)

func TestVerifyPeerCertificate_Success(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}

	evidence, err := VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err != nil {
		t.Fatalf("VerifyPeerCertificateAndEvidence failed: %v", err)
	}
	if evidence == nil {
		t.Fatal("expected non-nil evidence")
	}
}

func TestVerifyPeerCertificate_StrictVsPermissive(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	wrongMeasurement := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// 1. Strict mode with wrong measurement -> must fail with ErrMeasurementMismatch
	strictCfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: []string{wrongMeasurement},
	}
	_, err = VerifyPeerCertificateAndEvidence(certPEM, strictCfg)
	if err == nil {
		t.Fatal("expected error in strict mode with wrong measurement, got nil")
	}
	if !errors.Is(err, ErrMeasurementMismatch) {
		t.Fatalf("expected ErrMeasurementMismatch, got: %v", err)
	}

	// 2. Permissive mode with wrong measurement -> must succeed
	permissiveCfg := &Config{
		Mode:                 ModePermissive,
		ExpectedMeasurements: []string{wrongMeasurement},
	}
	evidence, err := VerifyPeerCertificateAndEvidence(certPEM, permissiveCfg)
	if err != nil {
		t.Fatalf("expected permissive mode to succeed with wrong measurement, got: %v", err)
	}
	if evidence == nil {
		t.Fatal("expected non-nil evidence in permissive mode")
	}
}

func TestVerifyPeerCertificate_PublicKeyBindingMismatch(t *testing.T) {
	mockProv := NewMockEvidenceProvider()

	// Generate keypair A
	privA, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	pubDERA, err := gx509.MarshalPKIXPublicKey(&privA.PublicKey)
	if err != nil {
		t.Fatalf("marshal key A: %v", err)
	}

	// Generate keypair B
	privB, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	// Attestation report binds Key A's digest
	pubDigestA := ComputePublicKeySM3(pubDERA)
	evidence, err := mockProv.GetEvidence(pubDigestA)
	if err != nil {
		t.Fatalf("get evidence for A: %v", err)
	}
	ext, err := EncodeCSVEvidence(evidence)
	if err != nil {
		t.Fatalf("encode csv evidence: %v", err)
	}

	// Create certificate using Key B, but attaching evidence bound to Key A
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &gx509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Mismatched Key Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []gx509.ExtKeyUsage{gx509.ExtKeyUsageServerAuth, gx509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       []pkix.Extension{ext},
	}

	certPEM, err := gx509.CreateCertificateToPem(template, template, &privB.PublicKey, privB)
	if err != nil {
		t.Fatalf("create certificate pem: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}

	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected ErrPublicKeyBindingMismatch, got nil")
	}
	if !errors.Is(err, ErrPublicKeyBindingMismatch) {
		t.Fatalf("expected ErrPublicKeyBindingMismatch, got: %v", err)
	}
}

func TestVerifyPeerCertificate_MissingExtension(t *testing.T) {
	// Generate certificate without CSV evidence extension
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &gx509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Certificate Without Evidence",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []gx509.ExtKeyUsage{gx509.ExtKeyUsageServerAuth, gx509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certPEM, err := gx509.CreateCertificateToPem(template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate pem: %v", err)
	}

	cfg := &Config{
		Mode: ModeStrict,
	}

	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected ErrMissingCSVEvidence, got nil")
	}
	if !errors.Is(err, ErrMissingCSVEvidence) {
		t.Fatalf("expected ErrMissingCSVEvidence, got: %v", err)
	}
}

func TestVerifyPeerCertificate_InsecureSkip(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	cfg := &Config{
		Mode:                          ModeStrict,
		InsecureSkipAttestationVerify: true,
		ExpectedMeasurements:          []string{"non-matching-measurement"},
	}

	evidence, err := VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err != nil {
		t.Fatalf("expected verify to pass when InsecureSkipAttestationVerify is true, got: %v", err)
	}
	if evidence == nil {
		t.Fatal("expected non-nil evidence")
	}
}

func TestConfig_Validate(t *testing.T) {
	// Default mode and timeout
	cfg := &Config{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error in strict mode without ExpectedMeasurements or EvidenceProvider")
	}

	mockProv := NewMockEvidenceProvider()
	cfgWithProv := &Config{
		EvidenceProvider: mockProv,
	}
	if err := cfgWithProv.Validate(); err != nil {
		t.Fatalf("expected valid config with EvidenceProvider, got: %v", err)
	}
	if cfgWithProv.Mode != ModeStrict {
		t.Fatalf("expected default ModeStrict, got: %s", cfgWithProv.Mode)
	}
	if cfgWithProv.Timeout != 10*time.Second {
		t.Fatalf("expected default Timeout 10s, got: %v", cfgWithProv.Timeout)
	}

	cfgWithMeas := &Config{
		ExpectedMeasurements: []string{hex.EncodeToString(make([]byte, 32))},
	}
	if err := cfgWithMeas.Validate(); err != nil {
		t.Fatalf("expected valid config with ExpectedMeasurements, got: %v", err)
	}

	cfgInvalidMode := &Config{
		Mode: "unknown-mode",
	}
	if err := cfgInvalidMode.Validate(); err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}

	cfgInsecure := &Config{
		Mode:                          ModeStrict,
		InsecureSkipAttestationVerify: true,
	}
	if err := cfgInsecure.Validate(); err != nil {
		t.Fatalf("expected valid config when InsecureSkipAttestationVerify is true, got: %v", err)
	}
}

func TestVerifyPeerCertificate_StrictModeEmptyMeasurements(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: nil,
	}

	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected error in strict mode with empty ExpectedMeasurements, got nil")
	}
	if !errors.Is(err, ErrMeasurementMismatch) {
		t.Fatalf("expected ErrMeasurementMismatch, got: %v", err)
	}
}

func TestVerifyPeerCertificate_ExpiredCertificate(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}
	pubDER, err := gx509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubDigest := ComputePublicKeySM3(pubDER)
	ev, err := mockProv.GetEvidence(pubDigest)
	if err != nil {
		t.Fatalf("get evidence: %v", err)
	}
	ext, err := EncodeCSVEvidence(ev)
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &gx509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Expired Cert"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	certPEM, err := gx509.CreateCertificateToPem(template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}
	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected error for expired cert, got nil")
	}
	if !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("expected ErrCertificateExpired, got: %v", err)
	}
}

func TestVerifyPeerCertificate_NotYetValidCertificate(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}
	pubDER, err := gx509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubDigest := ComputePublicKeySM3(pubDER)
	ev, err := mockProv.GetEvidence(pubDigest)
	if err != nil {
		t.Fatalf("get evidence: %v", err)
	}
	ext, err := EncodeCSVEvidence(ev)
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &gx509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Not Yet Valid Cert"},
		NotBefore:             time.Now().Add(1 * time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	certPEM, err := gx509.CreateCertificateToPem(template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}
	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected error for not yet valid cert, got nil")
	}
	if !errors.Is(err, ErrCertificateNotYetValid) {
		t.Fatalf("expected ErrCertificateNotYetValid, got: %v", err)
	}
}

func TestVerifyPeerCertificate_TamperedPEKSignature(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}
	pubDER, err := gx509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubDigest := ComputePublicKeySM3(pubDER)
	ev, err := mockProv.GetEvidence(pubDigest)
	if err != nil {
		t.Fatalf("get evidence: %v", err)
	}

	// Tamper a byte in the PEK signature (located at OffsetReportSig1 = 0x0c0)
	ev.Report[0x0c0+10] ^= 0xff

	ext, err := EncodeCSVEvidence(ev)
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &gx509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Tampered PEK Report"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	certPEM, err := gx509.CreateCertificateToPem(template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}
	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected error for tampered PEK signature, got nil")
	}
	if !errors.Is(err, ErrInvalidEvidenceReport) {
		t.Fatalf("expected ErrInvalidEvidenceReport, got: %v", err)
	}
}

func TestVerifyPeerCertificate_TamperedCertChain(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}
	pubDER, err := gx509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubDigest := ComputePublicKeySM3(pubDER)
	ev, err := mockProv.GetEvidence(pubDigest)
	if err != nil {
		t.Fatalf("get evidence: %v", err)
	}

	ev.HSKCekCert[20] ^= 0xff

	ext, err := EncodeCSVEvidence(ev)
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &gx509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Tampered Chain"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	certPEM, err := gx509.CreateCertificateToPem(template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}
	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected error for tampered cert chain, got nil")
	}
	if !errors.Is(err, ErrInvalidEvidenceReport) {
		t.Fatalf("expected ErrInvalidEvidenceReport, got: %v", err)
	}
}
