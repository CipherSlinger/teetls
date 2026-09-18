package csvattest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestConstantsMatchCSVABI(t *testing.T) {
	if ReportSize != 0x9f4 {
		t.Fatalf("ReportSize = %#x, want 0x9f4", ReportSize)
	}
	if getAttestationReportIOCT != 0xc0104401 {
		t.Fatalf("getAttestationReportIOCT = %#x, want 0xc0104401", getAttestationReportIOCT)
	}
	if OffsetReserved2+SealingKeySize != OffsetMAC {
		t.Fatalf("reserved2 should end at MAC offset")
	}
	if OffsetPEKCert+CSVCertSize+ChipIDSize+SealingKeySize != OffsetMAC {
		t.Fatalf("session MAC input should end at MAC offset")
	}
}

func TestUnmaskWords(t *testing.T) {
	plain := []byte{0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd}
	anonce := uint32(0x01020304)
	masked := make([]byte, len(plain))
	for i := 0; i < len(plain); i += 4 {
		word := binary.LittleEndian.Uint32(plain[i:i+4]) ^ anonce
		binary.LittleEndian.PutUint32(masked[i:i+4], word)
	}
	if got := UnmaskWords(masked, anonce); !bytes.Equal(got, plain) {
		t.Fatalf("UnmaskWords() = %x, want %x", got, plain)
	}
}

func TestVerifySessionMAC(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x11}, NonceSize)
	report := syntheticReport(nonce, bytes.Repeat([]byte{0x22}, SealingKeySize))
	if err := VerifySessionMAC(report, nonce); err != nil {
		t.Fatalf("VerifySessionMAC() error = %v", err)
	}

	report[OffsetMAC] ^= 0xff
	if err := VerifySessionMAC(report, nonce); !errors.Is(err, ErrSessionMAC) {
		t.Fatalf("VerifySessionMAC() error = %v, want ErrSessionMAC", err)
	}
}

func TestVerifyMNonce(t *testing.T) {
	nonce := []byte("1234567890abcdef")
	report := syntheticReport(nonce, bytes.Repeat([]byte{0x33}, SealingKeySize))
	if err := VerifyMNonce(report, nonce); err != nil {
		t.Fatalf("VerifyMNonce() error = %v", err)
	}

	wrongNonce := []byte("abcdef1234567890")
	if err := VerifyMNonce(report, wrongNonce); !errors.Is(err, ErrMNonceMismatch) {
		t.Fatalf("VerifyMNonce() error = %v, want ErrMNonceMismatch", err)
	}
}

func TestExtractSealingKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x44}, SealingKeySize)
	report := syntheticReport(bytes.Repeat([]byte{0x55}, NonceSize), want)
	got, err := ExtractSealingKey(report)
	if err != nil {
		t.Fatalf("ExtractSealingKey() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ExtractSealingKey() = %x, want %x", got, want)
	}
	report[OffsetReserved2] ^= 0xff
	if bytes.Equal(got, report[OffsetReserved2:OffsetReserved2+SealingKeySize]) {
		t.Fatalf("ExtractSealingKey() returned alias instead of copy")
	}
}

func syntheticReport(nonce, reserved2 []byte) []byte {
	report := make([]byte, ReportSize)
	anonce := uint32(0x10203040)
	binary.LittleEndian.PutUint32(report[OffsetANonce:OffsetANonce+4], anonce)
	for i := 0; i < NonceSize; i += 4 {
		word := binary.LittleEndian.Uint32(nonce[i:i+4]) ^ anonce
		binary.LittleEndian.PutUint32(report[OffsetMNonce+i:OffsetMNonce+i+4], word)
	}
	copy(report[OffsetReserved2:OffsetReserved2+SealingKeySize], reserved2)
	mac := hmacSM3(nonce, report[OffsetPEKCert:OffsetMAC])
	copy(report[OffsetMAC:OffsetMAC+HashSize], mac[:])
	return report
}
