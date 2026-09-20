package teetls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/CipherSlinger/teetls/pkg/csvattest"
)

var (
	// ErrMissingCSVEvidence indicates that the peer certificate lacks the CSV attestation extension.
	ErrMissingCSVEvidence = errors.New("certificate missing CSV attestation evidence extension")

	// ErrPublicKeyBindingMismatch indicates that the public key digest in the peer certificate does not match the attestation report USER_DATA.
	ErrPublicKeyBindingMismatch = errors.New("peer public key does not match attestation report USER_DATA")

	// ErrMeasurementMismatch indicates that the peer enclave measurement does not match any expected measurements.
	ErrMeasurementMismatch = errors.New("peer measurement hash does not match expected measurements")

	// ErrInvalidEvidenceReport indicates that the CSV attestation report data is corrupted or invalid.
	ErrInvalidEvidenceReport = errors.New("invalid or corrupted CSV attestation report")

	// ErrCertificateExpired indicates that the peer certificate has expired.
	ErrCertificateExpired = errors.New("peer certificate has expired")

	// ErrCertificateNotYetValid indicates that the peer certificate is not yet valid.
	ErrCertificateNotYetValid = errors.New("peer certificate is not yet valid")
)

// VerifyPeerCertificateAndEvidence parses the peer certificate, extracts the CSV attestation
// evidence extension, verifies cryptographic binding to the peer public key, and verifies
// enclave measurement against the configured policy.
func VerifyPeerCertificateAndEvidence(peerCertPEM []byte, cfg *Config) (*CSVEvidenceExtension, error) {
	if cfg == nil {
		cfg = &Config{Mode: ModeStrict}
	}

	cert, err := ParseCertificatePEM(peerCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse peer certificate: %w", err)
	}

	// 0. Verify certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("%w: not valid before %s (current time %s)", ErrCertificateNotYetValid, cert.NotBefore, now)
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: expired at %s (current time %s)", ErrCertificateExpired, cert.NotAfter, now)
	}

	var evidenceExtBytes []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDCSVEvidence) {
			evidenceExtBytes = ext.Value
			break
		}
	}

	if evidenceExtBytes == nil {
		return nil, ErrMissingCSVEvidence
	}

	evidence, err := DecodeCSVEvidence(evidenceExtBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidenceReport, err)
	}

	if cfg.InsecureSkipAttestationVerify {
		return evidence, nil
	}

	// 1. Verify PEK report signature and certificate chain
	opts := csvattest.VerifyOptions{
		VerifyChain: true,
	}
	if len(evidence.HRKCert) > 0 && len(evidence.HSKCekCert) > 0 {
		opts.HRKCertBytes = evidence.HRKCert
		opts.HSKCekCertBytes = evidence.HSKCekCert
	} else if cfg.HRKCertPath != "" && cfg.HSKCekCertPath != "" {
		opts.HRKCertPath = cfg.HRKCertPath
		opts.HSKCekCertPath = cfg.HSKCekCertPath
	} else if cfg.CertDir != "" {
		opts.CertDir = cfg.CertDir
	} else {
		opts.VerifyChain = false
	}

	res, err := csvattest.VerifyReportWithOptions(evidence.Report, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidenceReport, err)
	}

	// 2. Cryptographic Public Key Binding Check
	pubDigest := ComputePublicKeySM3(cert.RawSubjectPublicKeyInfo)
	if len(res.UserData) < 32 || !bytes.Equal(res.UserData[:32], pubDigest[:]) {
		return nil, fmt.Errorf("%w: expected %x", ErrPublicKeyBindingMismatch, pubDigest)
	}

	// 3. Measurement Check
	if cfg.Mode == ModeStrict && len(cfg.ExpectedMeasurements) == 0 {
		return nil, fmt.Errorf("%w: strict mode requires non-empty ExpectedMeasurements", ErrMeasurementMismatch)
	}

	if len(cfg.ExpectedMeasurements) > 0 {
		hexMeas := strings.ToLower(hex.EncodeToString(res.Digest))
		var measMatched bool
		for _, exp := range cfg.ExpectedMeasurements {
			if strings.EqualFold(exp, hexMeas) {
				measMatched = true
				break
			}
		}

		if !measMatched {
			if cfg.Mode == ModeStrict {
				return nil, fmt.Errorf("%w: got %s, expected one of %v", ErrMeasurementMismatch, hexMeas, cfg.ExpectedMeasurements)
			}
			// In ModePermissive, log warning and proceed without returning an error
			log.Printf("[WARN] [teetls] Enclave measurement mismatch in permissive mode: got %s, expected one of %v", hexMeas, cfg.ExpectedMeasurements)
		}
	}

	return evidence, nil
}
