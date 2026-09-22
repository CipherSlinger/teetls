package teetls

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/CipherSlinger/teetls/pkg/csvattest"
)

func TestCSVEvidenceExtension_EncodeDecode(t *testing.T) {
	orig := &CSVEvidenceExtension{
		Version:    1,
		Report:     bytes.Repeat([]byte{0xAA}, csvattest.ReportSize),
		HRKCert:    bytes.Repeat([]byte{0x11}, csvattest.HrkCertSize),
		HSKCekCert: bytes.Repeat([]byte{0x22}, csvattest.HskCekSize),
	}

	ext, err := EncodeCSVEvidence(orig)
	if err != nil {
		t.Fatalf("EncodeCSVEvidence failed: %v", err)
	}

	if !ext.Id.Equal(OIDCSVEvidence) {
		t.Fatalf("expected OID %s, got %s", OIDCSVEvidence, ext.Id)
	}
	if ext.Critical {
		t.Fatalf("expected Critical to be false")
	}

	decoded, err := DecodeCSVEvidence(ext.Value)
	if err != nil {
		t.Fatalf("DecodeCSVEvidence failed: %v", err)
	}

	if decoded.Version != orig.Version {
		t.Errorf("version mismatch: got %d, want %d", decoded.Version, orig.Version)
	}
	if !bytes.Equal(decoded.Report, orig.Report) {
		t.Errorf("report mismatch")
	}
	if !bytes.Equal(decoded.HRKCert, orig.HRKCert) {
		t.Errorf("hrk mismatch")
	}
	if !bytes.Equal(decoded.HSKCekCert, orig.HSKCekCert) {
		t.Errorf("hsk_cek mismatch")
	}
}

func TestCSVEvidenceExtension_OptionalFields(t *testing.T) {
	orig := &CSVEvidenceExtension{
		Version: 1,
		Report:  bytes.Repeat([]byte{0xBB}, csvattest.ReportSize),
	}

	ext, err := EncodeCSVEvidence(orig)
	if err != nil {
		t.Fatalf("EncodeCSVEvidence failed: %v", err)
	}

	decoded, err := DecodeCSVEvidence(ext.Value)
	if err != nil {
		t.Fatalf("DecodeCSVEvidence failed: %v", err)
	}

	if decoded.Version != orig.Version {
		t.Errorf("version mismatch: got %d, want %d", decoded.Version, orig.Version)
	}
	if !bytes.Equal(decoded.Report, orig.Report) {
		t.Errorf("report mismatch")
	}
	if len(decoded.HRKCert) != 0 {
		t.Errorf("expected empty hrk cert, got %v", decoded.HRKCert)
	}
	if len(decoded.HSKCekCert) != 0 {
		t.Errorf("expected empty hsk_cek cert, got %v", decoded.HSKCekCert)
	}
}

func TestCSVEvidenceExtension_DefaultVersion(t *testing.T) {
	// Version is omitted/0, should default to 1
	orig := &CSVEvidenceExtension{
		Report: bytes.Repeat([]byte{0xCC}, csvattest.ReportSize),
	}

	ext, err := EncodeCSVEvidence(orig)
	if err != nil {
		t.Fatalf("EncodeCSVEvidence failed: %v", err)
	}

	decoded, err := DecodeCSVEvidence(ext.Value)
	if err != nil {
		t.Fatalf("DecodeCSVEvidence failed: %v", err)
	}

	if decoded.Version != 1 {
		t.Errorf("expected version 1, got %d", decoded.Version)
	}
}

func TestCSVEvidenceExtension_RejectsUnknownVersion(t *testing.T) {
	report := bytes.Repeat([]byte{0xDD}, csvattest.ReportSize)

	// Encoding a version this package does not define must fail rather than
	// emit evidence that no conforming peer would accept.
	for _, v := range []int{-1, 2, 99} {
		if _, err := EncodeCSVEvidence(&CSVEvidenceExtension{Version: v, Report: report}); err == nil {
			t.Errorf("EncodeCSVEvidence accepted version %d, want an error", v)
		}
	}

	// Decoding must fail closed too: the version byte comes from the peer.
	// A version outside the defined set cannot be produced by the encoder, so
	// hand-build the DER with the same field layout.
	for _, v := range []int{-1, 2, 99} {
		der, err := asn1.Marshal(struct {
			Version    int    `asn1:"optional,default:1"`
			Report     []byte `asn1:"tag:0"`
			HRKCert    []byte `asn1:"tag:1,optional,omitempty"`
			HSKCekCert []byte `asn1:"tag:2,optional,omitempty"`
		}{Version: v, Report: report})
		if err != nil {
			t.Fatalf("marshal evidence with version %d: %v", v, err)
		}
		if _, err := DecodeCSVEvidence(der); err == nil {
			t.Errorf("DecodeCSVEvidence accepted version %d, want an error", v)
		}
	}

	// The defined version, and an omitted field (which asn1 decodes as the
	// declared default of 1), must both be accepted.
	ext, err := EncodeCSVEvidence(&CSVEvidenceExtension{Version: EvidenceVersion, Report: report})
	if err != nil {
		t.Fatalf("EncodeCSVEvidence(version %d) failed: %v", EvidenceVersion, err)
	}
	decoded, err := DecodeCSVEvidence(ext.Value)
	if err != nil {
		t.Fatalf("DecodeCSVEvidence(version %d) failed: %v", EvidenceVersion, err)
	}
	if decoded.Version != EvidenceVersion {
		t.Errorf("version = %d, want %d", decoded.Version, EvidenceVersion)
	}

	omitted, err := asn1.Marshal(struct {
		Report     []byte `asn1:"tag:0"`
		HRKCert    []byte `asn1:"tag:1,optional,omitempty"`
		HSKCekCert []byte `asn1:"tag:2,optional,omitempty"`
	}{Report: report})
	if err != nil {
		t.Fatalf("marshal evidence without a version field: %v", err)
	}
	decodedOmitted, err := DecodeCSVEvidence(omitted)
	if err != nil {
		t.Fatalf("DecodeCSVEvidence without a version field: %v", err)
	}
	if decodedOmitted.Version != EvidenceVersion {
		t.Errorf("omitted version decoded as %d, want the default %d", decodedOmitted.Version, EvidenceVersion)
	}
}

func TestCSVEvidenceExtension_ErrorCases(t *testing.T) {
	// Nil evidence
	if _, err := EncodeCSVEvidence(nil); err == nil {
		t.Errorf("expected error when encoding nil evidence, got nil")
	}

	// Empty report
	if _, err := EncodeCSVEvidence(&CSVEvidenceExtension{Report: nil}); err == nil {
		t.Errorf("expected error when encoding empty report, got nil")
	}

	// Invalid report size
	if _, err := EncodeCSVEvidence(&CSVEvidenceExtension{Report: []byte{0x01, 0x02, 0x03}}); err == nil {
		t.Errorf("expected error when encoding invalid report size, got nil")
	}

	// Invalid cert size
	if _, err := EncodeCSVEvidence(&CSVEvidenceExtension{
		Report:  bytes.Repeat([]byte{0x01}, csvattest.ReportSize),
		HRKCert: []byte{0x01},
	}); err == nil {
		t.Errorf("expected error when encoding invalid HRK cert size, got nil")
	}

	// Invalid ASN.1 bytes
	if _, err := DecodeCSVEvidence([]byte{0xFF, 0xFF}); err == nil {
		t.Errorf("expected error when decoding invalid ASN.1 data, got nil")
	}

	// Trailing bytes
	valid := &CSVEvidenceExtension{
		Version: 1,
		Report:  bytes.Repeat([]byte{0x01}, csvattest.ReportSize),
	}
	ext, err := EncodeCSVEvidence(valid)
	if err != nil {
		t.Fatalf("EncodeCSVEvidence failed: %v", err)
	}

	withTrailing := append(ext.Value, 0x00, 0x01)
	if _, err := DecodeCSVEvidence(withTrailing); err == nil {
		t.Errorf("expected error when decoding with trailing bytes, got nil")
	}
}
