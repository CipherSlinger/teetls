package teetls

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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

	// Deliberately a well-formed measurement that does not match the mock
	// provider's, so that the test shows InsecureSkipAttestationVerify bypassing
	// a real measurement mismatch rather than a malformed whitelist entry.
	cfg := &Config{
		Mode:                          ModeStrict,
		InsecureSkipAttestationVerify: true,
		ExpectedMeasurements:          []string{strings.Repeat("ab", 32)},
	}

	evidence, err := VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err != nil {
		t.Fatalf("expected verify to pass when InsecureSkipAttestationVerify is true, got: %v", err)
	}
	if evidence == nil {
		t.Fatal("expected non-nil evidence")
	}
}

func TestVerifyPeerCertificate_InsecureSkip_WithoutEvidence(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &gx509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Plain Certificate Without Evidence",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []gx509.ExtKeyUsage{gx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certPEM, err := gx509.CreateCertificateToPem(template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate pem: %v", err)
	}

	cfg := &Config{
		Mode:                          ModeStrict,
		InsecureSkipAttestationVerify: true,
	}

	evidence, err := VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err != nil {
		t.Fatalf("expected verify to pass without evidence when InsecureSkipAttestationVerify is true, got: %v", err)
	}
	if evidence != nil {
		t.Fatal("expected nil evidence for plain certificate")
	}
}

func TestConfig_Validate(t *testing.T) {
	// Validate is pure: it reports structural problems but never fills in
	// defaults, because a single Config is shared by many concurrent
	// connections. Effective values come from mode() and timeout() instead.
	cfg := &Config{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected structural default config to validate, got: %v", err)
	}
	if cfg.Mode != "" {
		t.Fatalf("Validate must not mutate Mode, got: %s", cfg.Mode)
	}
	if cfg.Timeout != 0 {
		t.Fatalf("Validate must not mutate Timeout, got: %v", cfg.Timeout)
	}
	if got := cfg.mode(); got != ModeStrict {
		t.Fatalf("mode() = %s, want %s", got, ModeStrict)
	}
	if got := cfg.timeout(); got != defaultTimeout {
		t.Fatalf("timeout() = %v, want %v", got, defaultTimeout)
	}

	mockProv := NewMockEvidenceProvider()
	cfgWithProv := &Config{
		EvidenceProvider: mockProv,
	}
	if err := cfgWithProv.Validate(); err != nil {
		t.Fatalf("expected valid config with EvidenceProvider, got: %v", err)
	}
	if got := cfgWithProv.mode(); got != ModeStrict {
		t.Fatalf("mode() = %s, want %s", got, ModeStrict)
	}
	if got := cfgWithProv.timeout(); got != defaultTimeout {
		t.Fatalf("timeout() = %v, want %v", got, defaultTimeout)
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

	// Explicit values must be honoured unchanged by the accessors.
	cfgExplicit := &Config{Mode: ModePermissive, Timeout: 3 * time.Second}
	if got := cfgExplicit.mode(); got != ModePermissive {
		t.Fatalf("mode() = %s, want %s", got, ModePermissive)
	}
	if got := cfgExplicit.timeout(); got != 3*time.Second {
		t.Fatalf("timeout() = %v, want %v", got, 3*time.Second)
	}

	// Half-configured key material must be rejected.
	cfgHalfCert := &Config{CertPEM: []byte("pem")}
	if err := cfgHalfCert.Validate(); err == nil {
		t.Fatal("expected error for CertPEM without KeyPEM, got nil")
	}
	cfgHalfHRK := &Config{HRKCertPath: "/tmp/hrk.cert"}
	if err := cfgHalfHRK.Validate(); err == nil {
		t.Fatal("expected error for HRKCertPath without HSKCekCertPath, got nil")
	}

	// A well-formed whitelist, in either letter case, must be accepted: the
	// verifier compares with EqualFold, so case cannot be constrained.
	for _, m := range []string{
		strings.Repeat("ab", 32),
		strings.ToUpper(strings.Repeat("ab", 32)),
	} {
		cfgCase := &Config{ExpectedMeasurements: []string{m}}
		if err := cfgCase.Validate(); err != nil {
			t.Fatalf("expected %q to validate, got: %v", m, err)
		}
	}

	// Whichever entry of a whitelist is malformed must be reported.
	good := strings.Repeat("ab", 32)
	for name, m := range map[string]string{
		"empty":          "",
		"too short":      "deadbeef01234567",
		"too long":       good + "ab",
		"non-hex":        strings.Repeat("zz", 32),
		"0x prefix":      "0x" + good[:62],
		"inner space":    good[:32] + " " + good[33:],
		"trailing space": good + " ",
	} {
		cfgBad := &Config{ExpectedMeasurements: []string{good, m}}
		if err := cfgBad.Validate(); err == nil {
			t.Errorf("expected an error for a %s measurement, got nil", name)
		}
	}

	// A measurement of exactly the right length but with one character replaced
	// by a non-hex byte must still be caught.
	cfgNonHex := &Config{ExpectedMeasurements: []string{good[:63] + "g"}}
	if err := cfgNonHex.Validate(); err == nil {
		t.Error("expected an error for a 64-character non-hex measurement, got nil")
	}
}

// TestVerifyPeerCertificate_RejectsMalformedMeasurements verifies that the
// measurement whitelist is validated on the verification path too, which is
// reachable without Config.Validate.
func TestVerifyPeerCertificate_RejectsMalformedMeasurements(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
		ExpectedMeasurements: []string{"not-a-measurement"},
	}

	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err == nil {
		t.Fatal("expected a configuration error for a malformed measurement, got nil")
	}
	// It must be reported as a configuration problem, not as a policy rejection.
	if errors.Is(err, ErrMeasurementMismatch) {
		t.Fatalf("malformed measurement reported as a mismatch rather than a config error: %v", err)
	}
	if !strings.Contains(err.Error(), "ExpectedMeasurements") {
		t.Fatalf("error does not name the offending field: %v", err)
	}
}

// TestConfigValidate_Concurrent verifies that Validate is safe to call from many
// goroutines sharing one Config, which is how Listen hands it to each Accept.
func TestConfigValidate_Concurrent(t *testing.T) {
	cfg := &Config{ExpectedMeasurements: []string{hex.EncodeToString(make([]byte, 32))}}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			_ = cfg.mode()
			_ = cfg.timeout()
		}()
	}
	wg.Wait()
}

func TestVerifyPeerCertificate_StrictModeEmptyMeasurements(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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
		TrustedHRKCert:       mockProv.TrustedHRKCert(),
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

// writeCertChainDir writes a mock HRK anchor and HSK/CEK bundle into a fresh
// directory laid out the way Config.CertDir expects.
func writeCertChainDir(t *testing.T, hrk, hskCek []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hrk.cert"), hrk, 0o600); err != nil {
		t.Fatalf("write hrk.cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hsk_cek.cert"), hskCek, 0o600); err != nil {
		t.Fatalf("write hsk_cek.cert: %v", err)
	}
	return dir
}

// TestVerifyPeerCertificateWithEvidence_CertDir covers the offline trust path:
// the chain material comes from a local directory rather than the peer.
func TestVerifyPeerCertificateWithEvidence_CertDir(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	dir := writeCertChainDir(t, mockProv.HRKCert, mockProv.HSKCekCert)
	cfg := &Config{
		Mode:                 ModeStrict,
		CertDir:              dir,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}

	evidence, err := VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if err != nil {
		t.Fatalf("verification with CertDir failed: %v", err)
	}
	if evidence == nil {
		t.Fatal("expected evidence, got nil")
	}
}

// TestVerifyPeerCertificateWithEvidence_CertDirUntrustedChain checks that a
// local directory holding the wrong chain material is rejected rather than
// silently skipping chain verification.
func TestVerifyPeerCertificateWithEvidence_CertDirUntrustedChain(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	other := NewMockEvidenceProvider()
	if bytes.Equal(other.HRKCert, mockProv.HRKCert) {
		t.Fatal("expected two distinct mock authorities")
	}
	dir := writeCertChainDir(t, other.HRKCert, other.HSKCekCert)

	cfg := &Config{
		Mode:                 ModeStrict,
		CertDir:              dir,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}
	if _, err := VerifyPeerCertificateAndEvidence(certPEM, cfg); err == nil {
		t.Fatal("expected an untrusted local chain to be rejected, got nil error")
	}
}

// TestVerifyPeerCertificateWithEvidence_CertDirMissing checks that a CertDir
// without the expected files is reported as an error.
func TestVerifyPeerCertificateWithEvidence_CertDirMissing(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	cfg := &Config{
		Mode:                 ModeStrict,
		CertDir:              t.TempDir(),
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}
	_, err = VerifyPeerCertificateAndEvidence(certPEM, cfg)
	if !errors.Is(err, ErrInvalidEvidenceReport) {
		t.Fatalf("expected ErrInvalidEvidenceReport for an empty CertDir, got: %v", err)
	}
}

// TestVerifyPeerCertificateWithEvidence_TrustedHRKTrailingNewline checks that a
// trust anchor read from a file with a trailing newline still matches, and that
// a genuinely different anchor is still rejected.
func TestVerifyPeerCertificateWithEvidence_TrustedHRKTrailingNewline(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, _, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	dir := writeCertChainDir(t, mockProv.HRKCert, mockProv.HSKCekCert)
	cfg := &Config{
		Mode:                 ModeStrict,
		CertDir:              dir,
		TrustedHRKCert:       append(append([]byte(nil), mockProv.HRKCert...), '\n'),
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}
	if _, err := VerifyPeerCertificateAndEvidence(certPEM, cfg); err != nil {
		t.Fatalf("trailing newline in the trust anchor should be ignored, got: %v", err)
	}

	// A short anchor cannot be a certificate and must be rejected outright.
	cfg.TrustedHRKCert = mockProv.HRKCert[:16]
	if _, err := VerifyPeerCertificateAndEvidence(certPEM, cfg); !errors.Is(err, ErrInvalidEvidenceReport) {
		t.Fatalf("expected ErrInvalidEvidenceReport for a truncated anchor, got: %v", err)
	}
}
