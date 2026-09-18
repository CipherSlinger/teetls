package csvattest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestVMMCallUnsupported(t *testing.T) {
	report := make([]byte, ReportSize)
	if err := GetAttestationReportVMMCall(report); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("GetAttestationReportVMMCall() error = %v, want ErrUnsupported", err)
	}

	key := make([]byte, SealingKeySize)
	if err := GetSealingKeyVMMCall(key); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("GetSealingKeyVMMCall() error = %v, want ErrUnsupported", err)
	}
}

func TestShortBuffers(t *testing.T) {
	if err := GetAttestationReportVMMCall(make([]byte, ReportSize-1)); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("GetAttestationReportVMMCall(short) error = %v, want ErrShortBuffer", err)
	}
	if err := GetSealingKeyVMMCall(make([]byte, SealingKeySize-1)); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("GetSealingKeyVMMCall(short) error = %v, want ErrShortBuffer", err)
	}
}

func TestUserDataDefaultsAndValidation(t *testing.T) {
	t.Setenv("ATTESTATION_USERDATA", "")
	got, err := NewClient().userData()
	if err != nil {
		t.Fatalf("default userData() error = %v", err)
	}
	want := make([]byte, UserDataSize)
	copy(want, defaultUserDataText)
	if !bytes.Equal(got, want) {
		t.Fatalf("default userData() = %x, want %x", got, want)
	}

	explicit := bytes.Repeat([]byte{0x7a}, UserDataSize)
	got, err = NewClient(WithUserData(explicit)).userData()
	if err != nil {
		t.Fatalf("explicit userData() error = %v", err)
	}
	if !bytes.Equal(got, explicit) {
		t.Fatalf("explicit userData() = %x, want %x", got, explicit)
	}
	explicit[0] ^= 0xff
	if bytes.Equal(got, explicit) {
		t.Fatalf("explicit userData() returned alias")
	}

	t.Setenv("ATTESTATION_USERDATA", hex.EncodeToString(bytes.Repeat([]byte{0x5c}, UserDataSize)))
	got, err = NewClient().userData()
	if err != nil {
		t.Fatalf("env userData() error = %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x5c}, UserDataSize)) {
		t.Fatalf("env userData() = %x", got)
	}

	if _, err := NewClient(WithUserData([]byte{1, 2, 3})).userData(); !errors.Is(err, ErrInvalidUserData) {
		t.Fatalf("short explicit userData() error = %v, want ErrInvalidUserData", err)
	}
	t.Setenv("ATTESTATION_USERDATA", "abcd")
	if _, err := NewClient().userData(); !errors.Is(err, ErrInvalidUserData) {
		t.Fatalf("short env userData() error = %v, want ErrInvalidUserData", err)
	}
	t.Setenv("ATTESTATION_USERDATA", string(bytes.Repeat([]byte{'z'}, UserDataSize*2)))
	if _, err := NewClient().userData(); !errors.Is(err, ErrInvalidUserData) {
		t.Fatalf("invalid env userData() error = %v, want ErrInvalidUserData", err)
	}
}

func TestVerifyAttestationReportValidation(t *testing.T) {
	if err := VerifyAttestationReport(make([]byte, ReportSize-1), false); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("VerifyAttestationReport(short) error = %v, want ErrShortBuffer", err)
	}
	if err := VerifyAttestationReport(make([]byte, ReportSize), false); err == nil {
		t.Fatalf("VerifyAttestationReport(malformed) error = nil, want non-nil")
	}
}
