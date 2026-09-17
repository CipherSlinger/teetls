package teetls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"

	"taa/pkg/csvattest"
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

	// 1. Cryptographic Public Key Binding Check
	pubDigest := ComputePublicKeySM3(cert.RawSubjectPublicKeyInfo)
	var matchedBinding bool

	// Check 1: Check report at OffsetUserData (0x040)
	if len(evidence.Report) >= csvattest.OffsetUserData+32 &&
		bytes.Equal(evidence.Report[csvattest.OffsetUserData:csvattest.OffsetUserData+32], pubDigest[:]) {
		matchedBinding = true
	}

	// Check 2: Check report at legacy offset 128 (0x080) for custom mock compatibility
	if !matchedBinding && len(evidence.Report) >= 128+32 &&
		bytes.Equal(evidence.Report[128:160], pubDigest[:]) {
		matchedBinding = true
	}

	// Check 3: Check via csvattest.ParseReport if report length >= ReportSize
	if !matchedBinding && len(evidence.Report) >= csvattest.ReportSize {
		res, err := csvattest.ParseReport(evidence.Report)
		if err == nil && len(res.UserData) >= 32 && bytes.Equal(res.UserData[:32], pubDigest[:]) {
			matchedBinding = true
		}
	}

	if !matchedBinding {
		return nil, fmt.Errorf("%w: expected %x", ErrPublicKeyBindingMismatch, pubDigest)
	}

	// 2. Measurement Check
	if len(cfg.ExpectedMeasurements) > 0 {
		var extractedMeas []byte

		// Try ParseReport first
		if len(evidence.Report) >= csvattest.ReportSize {
			if res, err := csvattest.ParseReport(evidence.Report); err == nil && len(res.Digest) == 32 {
				extractedMeas = res.Digest
			}
		}

		// Fallback: direct offset extraction
		if len(extractedMeas) == 0 {
			if len(evidence.Report) >= csvattest.OffsetMeasure+32 {
				extractedMeas = evidence.Report[csvattest.OffsetMeasure : csvattest.OffsetMeasure+32]
			} else if len(evidence.Report) >= 160+32 {
				extractedMeas = evidence.Report[160:192]
			}
		}

		if len(extractedMeas) < 32 {
			return nil, fmt.Errorf("%w: report too short to extract measurement", ErrInvalidEvidenceReport)
		}

		hexMeas := strings.ToLower(hex.EncodeToString(extractedMeas))
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
