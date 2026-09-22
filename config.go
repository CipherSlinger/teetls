package teetls

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// defaultTimeout bounds dialing, handshaking and attestation verification when
// Config.Timeout is unset.
const defaultTimeout = 10 * time.Second

// AttestationMode defines the policy mode for remote attestation verification.
type AttestationMode string

const (
	// ModeStrict requires valid hardware attestation and measurement whitelist match.
	ModeStrict AttestationMode = "strict"
	// ModePermissive requires valid hardware identity & public key binding, and logs warnings if measurement does not match whitelist.
	ModePermissive AttestationMode = "permissive"
)

// Config configures TEE-TLS mutual/remote attestation settings and policies.
type Config struct {
	// Mode specifies the attestation policy mode (defaults to ModeStrict).
	Mode AttestationMode

	// EvidenceProvider supplies attestation evidence when acting as server or client.
	EvidenceProvider EvidenceProvider

	// ExpectedMeasurements is the list of accepted SM3 measurement hex strings (whitelist).
	ExpectedMeasurements []string

	// VerifyMutualAttestation enables attestation verification of client certificates.
	VerifyMutualAttestation bool

	// Timeout specifies the timeout for attestation verification operations (defaults to 10s if <= 0).
	Timeout time.Duration

	// InsecureSkipAttestationVerify bypasses attestation verification (for testing only).
	InsecureSkipAttestationVerify bool

	// CertPEM and KeyPEM hold optional pre-generated SM2 certificate and private key in PEM format.
	CertPEM []byte
	KeyPEM  []byte

	// HRKCertPath and HSKCekCertPath specify explicit paths to the local Hygon certificate chain.
	// HRKCertPath is the trusted root anchor; HSKCekCertPath is the intermediate bundle.
	HRKCertPath    string
	HSKCekCertPath string

	// TrustedHRKCert contains an optional in-memory trusted HRK root anchor.
	TrustedHRKCert []byte

	// CertDir specifies a directory containing hrk.cert and hsk_cek.cert.
	CertDir string

	// CertCacheTTL specifies the duration to cache dynamically generated server certificate and evidence.
	// Defaults to 1 hour if <= 0.
	CertCacheTTL time.Duration

	certMu         sync.RWMutex
	cachedCertPEM  []byte
	cachedKeyPEM   []byte
	cachedAt       time.Time
	cachedNotAfter time.Time
}

// GetOrGenerateCertificate retrieves the cached certificate/key or generates a new one.
func (c *Config) GetOrGenerateCertificate() ([]byte, []byte, error) {
	return c.GetOrGenerateCertificateContext(context.Background())
}

// GetOrGenerateCertificateContext retrieves or generates a certificate with cancellable evidence retrieval.
func (c *Config) GetOrGenerateCertificateContext(ctx context.Context) ([]byte, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(c.CertPEM) > 0 && len(c.KeyPEM) > 0 {
		return append([]byte(nil), c.CertPEM...), append([]byte(nil), c.KeyPEM...), nil
	}

	if c.EvidenceProvider == nil {
		return nil, nil, errors.New("teetls: requires either CertPEM/KeyPEM or EvidenceProvider")
	}

	c.certMu.RLock()
	ttl := c.CertCacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if c.cachedCertificateValidLocked(ttl) {
		certPEM := append([]byte(nil), c.cachedCertPEM...)
		keyPEM := append([]byte(nil), c.cachedKeyPEM...)
		c.certMu.RUnlock()
		return certPEM, keyPEM, nil
	}
	c.certMu.RUnlock()

	c.certMu.Lock()
	defer c.certMu.Unlock()
	if c.cachedCertificateValidLocked(ttl) {
		return append([]byte(nil), c.cachedCertPEM...), append([]byte(nil), c.cachedKeyPEM...), nil
	}

	certPEM, keyPEM, err := GenerateSM2CertificateWithEvidenceContext(ctx, c.EvidenceProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate: %w", err)
	}

	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated certificate: %w", err)
	}

	c.cachedCertPEM = append([]byte(nil), certPEM...)
	c.cachedKeyPEM = append([]byte(nil), keyPEM...)
	c.cachedAt = time.Now()
	c.cachedNotAfter = cert.NotAfter
	return append([]byte(nil), certPEM...), append([]byte(nil), keyPEM...), nil
}

func (c *Config) cachedCertificateValidLocked(ttl time.Duration) bool {
	if len(c.cachedCertPEM) == 0 || len(c.cachedKeyPEM) == 0 {
		return false
	}
	if time.Since(c.cachedAt) >= ttl {
		return false
	}
	if c.cachedNotAfter.IsZero() {
		return false
	}
	return time.Now().Add(time.Minute).Before(c.cachedNotAfter)
}

// Validate reports whether the configuration is structurally valid.
//
// It never modifies the receiver. A single Config is routinely shared by many
// concurrent connections (see Listen), so Validate must remain safe to call
// from those goroutines; defaults are applied at their point of use through
// mode and timeout instead.
func (c *Config) Validate() error {
	if c.Mode != "" && c.Mode != ModeStrict && c.Mode != ModePermissive {
		return fmt.Errorf("invalid attestation mode: %q (must be %q or %q)", c.Mode, ModeStrict, ModePermissive)
	}

	if (len(c.CertPEM) == 0) != (len(c.KeyPEM) == 0) {
		return errors.New("teetls: CertPEM and KeyPEM must be configured together")
	}

	if (c.HRKCertPath == "") != (c.HSKCekCertPath == "") {
		return errors.New("teetls: HRKCertPath and HSKCekCertPath must be configured together")
	}

	return nil
}

// mode returns the effective attestation mode, defaulting to ModeStrict.
func (c *Config) mode() AttestationMode {
	if c.Mode == "" {
		return ModeStrict
	}
	return c.Mode
}

// timeout returns the effective timeout, defaulting to defaultTimeout.
func (c *Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return defaultTimeout
	}
	return c.Timeout
}
