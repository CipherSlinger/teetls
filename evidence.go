package teetls

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// OIDCSVEvidence is the registered ASN.1 Object Identifier for Hygon CSV RA-TLS evidence.
var OIDCSVEvidence = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58270, 1, 1}

// CSVEvidenceExtension holds the attestation report and cert chain for CSV RA-TLS.
type CSVEvidenceExtension struct {
	Version    int    `asn1:"default:1"`
	Report     []byte `asn1:"tag:0"`
	HRKCert    []byte `asn1:"tag:1,optional"`
	HSKCekCert []byte `asn1:"tag:2,optional"`
}

// EncodeCSVEvidence encodes the evidence extension into a pkix.Extension.
func EncodeCSVEvidence(ev *CSVEvidenceExtension) (pkix.Extension, error) {
	if ev == nil {
		return pkix.Extension{}, errors.New("nil evidence extension")
	}
	val, err := asn1.Marshal(*ev)
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
	return &ev, nil
}
