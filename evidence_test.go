package teetls

import (
	"bytes"
	"testing"
)

func TestCSVEvidenceExtension_EncodeDecode(t *testing.T) {
	orig := &CSVEvidenceExtension{
		Version:    1,
		Report:     bytes.Repeat([]byte{0xAA}, 2048),
		HRKCert:    []byte("fake-hrk-cert-bytes"),
		HSKCekCert: []byte("fake-hsk-cek-cert-bytes"),
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
		Report:  bytes.Repeat([]byte{0xBB}, 2048),
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
		Report: bytes.Repeat([]byte{0xCC}, 2048),
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

func TestCSVEvidenceExtension_ErrorCases(t *testing.T) {
	// Nil evidence
	if _, err := EncodeCSVEvidence(nil); err == nil {
		t.Errorf("expected error when encoding nil evidence, got nil")
	}

	// Empty report
	if _, err := EncodeCSVEvidence(&CSVEvidenceExtension{Report: nil}); err == nil {
		t.Errorf("expected error when encoding empty report, got nil")
	}

	// Invalid ASN.1 bytes
	if _, err := DecodeCSVEvidence([]byte{0xFF, 0xFF}); err == nil {
		t.Errorf("expected error when decoding invalid ASN.1 data, got nil")
	}

	// Trailing bytes
	valid := &CSVEvidenceExtension{
		Version: 1,
		Report:  []byte{0x01, 0x02, 0x03},
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
