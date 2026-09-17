package teetls

import (
	"errors"
	"fmt"
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
		if len(c.ExpectedMeasurements) == 0 && c.EvidenceProvider == nil {
			return errors.New("strict attestation mode requires either ExpectedMeasurements or EvidenceProvider")
		}
	}

	return nil
}
