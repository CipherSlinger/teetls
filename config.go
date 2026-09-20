package teetls

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

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

	// HRKCertPath and HSKCekCertPath specify explicit paths to Hygon CA certificate chain.
	HRKCertPath    string
	HSKCekCertPath string

	// CertDir specifies a directory containing hrk.cert and hsk_cek.cert.
	CertDir string

	// CertCacheTTL specifies the duration to cache dynamically generated server certificate and evidence.
	// Defaults to 1 hour if <= 0.
	CertCacheTTL time.Duration

	certMu        sync.RWMutex
	cachedCertPEM []byte
	cachedKeyPEM  []byte
	cachedAt      time.Time
}

// GetOrGenerateCertificate retrieves the cached certificate/key or generates a new one.
func (c *Config) GetOrGenerateCertificate() ([]byte, []byte, error) {
	if len(c.CertPEM) > 0 && len(c.KeyPEM) > 0 {
		return c.CertPEM, c.KeyPEM, nil
	}

	if c.EvidenceProvider == nil {
		return nil, nil, errors.New("teetls: requires either CertPEM/KeyPEM or EvidenceProvider")
	}

	c.certMu.RLock()
	ttl := c.CertCacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if len(c.cachedCertPEM) > 0 && len(c.cachedKeyPEM) > 0 && time.Since(c.cachedAt) < ttl {
		certPEM, keyPEM := c.cachedCertPEM, c.cachedKeyPEM
		c.certMu.RUnlock()
		return certPEM, keyPEM, nil
	}
	c.certMu.RUnlock()

	c.certMu.Lock()
	defer c.certMu.Unlock()
	if len(c.cachedCertPEM) > 0 && len(c.cachedKeyPEM) > 0 && time.Since(c.cachedAt) < ttl {
		return c.cachedCertPEM, c.cachedKeyPEM, nil
	}

	certPEM, keyPEM, err := GenerateSM2CertificateWithEvidence(c.EvidenceProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate: %w", err)
	}

	c.cachedCertPEM = certPEM
	c.cachedKeyPEM = keyPEM
	c.cachedAt = time.Now()
	return certPEM, keyPEM, nil
}

// Validate validates the configuration and applies sensible defaults.
func (c *Config) Validate() error {
	if c.Mode == "" {
		c.Mode = ModeStrict
	}

	if c.Mode != ModeStrict && c.Mode != ModePermissive {
		return fmt.Errorf("invalid attestation mode: %q (must be %q or %q)", c.Mode, ModeStrict, ModePermissive)
	}

	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}

	if c.Mode == ModeStrict && !c.InsecureSkipAttestationVerify {
		if len(c.ExpectedMeasurements) == 0 && c.EvidenceProvider == nil && len(c.CertPEM) == 0 {
			return errors.New("strict attestation mode requires either ExpectedMeasurements, EvidenceProvider, or CertPEM")
		}
	}

	return nil
}
