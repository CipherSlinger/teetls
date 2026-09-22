package teetls

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/CipherSlinger/teetls/pkg/csvattest"
)

// OIDCSVEvidence is the registered ASN.1 Object Identifier for Hygon CSV RA-TLS evidence.
var OIDCSVEvidence = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58270, 1, 1}

// EvidenceVersion is the only csv evidence layout version this package encodes
// or accepts. Decoding fails closed on any other value rather than silently
// treating unknown evidence as version 1.
const EvidenceVersion = 1

// errNilEvidence is returned when an evidence extension is passed as nil.
var errNilEvidence = errors.New("nil evidence extension")

// CSVEvidenceExtension holds the attestation report and cert chain for CSV RA-TLS.
type CSVEvidenceExtension struct {
	Version    int    `asn1:"optional,default:1"`
	Report     []byte `asn1:"tag:0"`
	HRKCert    []byte `asn1:"tag:1,optional,omitempty"`
	HSKCekCert []byte `asn1:"tag:2,optional,omitempty"`
}

// EncodeCSVEvidence encodes the evidence extension into a pkix.Extension.
func EncodeCSVEvidence(ev *CSVEvidenceExtension) (pkix.Extension, error) {
	if ev == nil {
		return pkix.Extension{}, errNilEvidence
	}

	// A zero Version means the caller left the field unset; normalise it before
	// validating so that the default is not rejected as an unknown version.
	evCopy := *ev
	if evCopy.Version == 0 {
		evCopy.Version = EvidenceVersion
	}
	if err := validateEvidenceExtension(&evCopy); err != nil {
		return pkix.Extension{}, err
	}

	val, err := asn1.Marshal(evCopy)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal csv evidence: %w", err)
	}
	return pkix.Extension{
		Id:       OIDCSVEvidence,
		Critical: false,
		Value:    val,
	}, nil
}

// DecodeCSVEvidence unmarshals a CSVEvidenceExtension from DER bytes.
func DecodeCSVEvidence(data []byte) (*CSVEvidenceExtension, error) {
	var ev CSVEvidenceExtension
	rest, err := asn1.Unmarshal(data, &ev)
	if err != nil {
		return nil, fmt.Errorf("unmarshal csv evidence: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing bytes in csv evidence extension")
	}
	if err := validateEvidenceExtension(&ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

func validateEvidenceExtension(ev *CSVEvidenceExtension) error {
	if ev == nil {
		return errNilEvidence
	}
	if ev.Version != EvidenceVersion {
		return fmt.Errorf("unsupported csv evidence version %d, want %d", ev.Version, EvidenceVersion)
	}
	if len(ev.Report) != csvattest.ReportSize {
		return fmt.Errorf("invalid report size in evidence extension: got %d, want %d", len(ev.Report), csvattest.ReportSize)
	}
	if len(ev.HRKCert) > 0 && len(ev.HRKCert) != csvattest.HrkCertSize {
		return fmt.Errorf("invalid HRK cert size in evidence extension: got %d, want %d", len(ev.HRKCert), csvattest.HrkCertSize)
	}
	if len(ev.HSKCekCert) > 0 && len(ev.HSKCekCert) != csvattest.HskCekSize {
		return fmt.Errorf("invalid HSK/CEK cert size in evidence extension: got %d, want %d", len(ev.HSKCekCert), csvattest.HskCekSize)
	}
	return nil
}
