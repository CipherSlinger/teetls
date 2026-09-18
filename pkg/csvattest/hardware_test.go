//go:build csv_hardware && linux && amd64

package csvattest

import (
	"crypto/rand"
	"os"
	"testing"
)

func TestHardwareIOCTL(t *testing.T) {
	if _, err := os.Stat(defaultCSVGuestDevice); err != nil {
		t.Skipf("%s unavailable: %v", defaultCSVGuestDevice, err)
	}

	report := make([]byte, ReportSize)
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	if err := GetAttestationReportIOCTL(report, nonce); err != nil {
		t.Fatalf("GetAttestationReportIOCTL: %v", err)
	}
	if err := VerifyAttestationReport(report, false); err != nil {
		t.Fatalf("VerifyAttestationReport: %v", err)
	}
}
