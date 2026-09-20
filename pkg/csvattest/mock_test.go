package csvattest

import (
	"encoding/hex"
	"testing"
)

func TestGenerateMockAttestationData(t *testing.T) {
	userData := []byte("0123456789abcdef0123456789abcdef")
	measurementHex := "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

	report, hrkCert, hskCekCert, err := GenerateMockAttestationData(userData, measurementHex)
	if err != nil {
		t.Fatalf("GenerateMockAttestationData failed: %v", err)
	}

	opts := VerifyOptions{
		HRKCertBytes:    hrkCert,
		HSKCekCertBytes: hskCekCert,
	}

	res, err := VerifyReportWithOptions(report, opts)
	if err != nil {
		t.Fatalf("VerifyReportWithOptions failed on mock data: %v", err)
	}

	if hex.EncodeToString(res.Digest) != measurementHex {
		t.Fatalf("expected measurement %s, got %x", measurementHex, res.Digest)
	}

	if string(res.UserData[:len(userData)]) != string(userData) {
		t.Fatalf("expected user data %s, got %s", userData, res.UserData)
	}
}
