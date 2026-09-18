//go:build !linux || !amd64

package csvattest

import (
	"errors"
	"testing"
)

func TestIOCTLUnsupported(t *testing.T) {
	report := make([]byte, ReportSize)
	nonce := make([]byte, NonceSize)
	if err := GetAttestationReportIOCTL(report, nonce); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("GetAttestationReportIOCTL() error = %v, want ErrUnsupported", err)
	}
	key := make([]byte, SealingKeySize)
	if err := GetSealingKeyIOCTL(key); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("GetSealingKeyIOCTL() error = %v, want ErrUnsupported", err)
	}
}
