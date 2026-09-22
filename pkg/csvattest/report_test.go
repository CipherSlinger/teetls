package csvattest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestConstantsMatchCSVABI(t *testing.T) {
	// Values pinned directly against the Hygon CSV guest ABI. If the driver
	// changes the report layout these must be updated deliberately, so they are
	// spelled out as literals rather than derived from each other.
	if ReportSize != 0x9f4 {
		t.Fatalf("ReportSize = %#x, want 0x9f4", ReportSize)
	}
	if SignedSize != 0xb4 {
		t.Fatalf("SignedSize = %#x, want 0xb4", SignedSize)
	}
	if OffsetANonce != 0x0bc {
		t.Fatalf("OffsetANonce = %#x, want 0x0bc", OffsetANonce)
	}
	if OffsetReportSig1 != 0x0c0 {
		t.Fatalf("OffsetReportSig1 = %#x, want 0x0c0", OffsetReportSig1)
	}
	if OffsetPEKCert != 0x150 {
		t.Fatalf("OffsetPEKCert = %#x, want 0x150", OffsetPEKCert)
	}
	if OffsetChipID != 0x974 {
		t.Fatalf("OffsetChipID = %#x, want 0x974", OffsetChipID)
	}
	if OffsetMAC != 0x9d4 {
		t.Fatalf("OffsetMAC = %#x, want 0x9d4", OffsetMAC)
	}
	if HrkCertSize != 0x340 {
		t.Fatalf("HrkCertSize = %#x, want 0x340", HrkCertSize)
	}
	if CSVCertSize != 0x824 {
		t.Fatalf("CSVCertSize = %#x, want 0x824", CSVCertSize)
	}
	if getAttestationReportIOCT != 0xc0104401 {
		t.Fatalf("getAttestationReportIOCT = %#x, want 0xc0104401", getAttestationReportIOCT)
	}
	// The ioctl encoding packs the descriptor size into bits 16..29, so the
	// descriptor the kernel sees must match the struct we pass.
	if getAttestationReportIOCT>>16&0x3fff != csvGuestMemSize {
		t.Fatalf("ioctl encodes descriptor size %d, want %d", getAttestationReportIOCT>>16&0x3fff, csvGuestMemSize)
	}

	// The PEK signature is computed over the report prefix [0, SignedSize).
	// Every field the verifier treats as authenticated must lie inside it.
	signedFields := []struct {
		name  string
		off   int
		width int
	}{
		{"report pubkey digest", OffsetReportPubkeyDigest, HashSize},
		{"VM ID", OffsetReportVMID, 16},
		{"VM version", OffsetReportVMVersion, 16},
		{"user data", OffsetUserData, UserDataSize},
		{"M nonce", OffsetMNonce, NonceSize},
		{"measurement", OffsetMeasure, HashSize},
		{"policy", OffsetReportPolicy, 4},
	}
	for _, f := range signedFields {
		if f.off+f.width > SignedSize {
			t.Errorf("%s spans [%#x,%#x) which is outside the signed region [0,%#x)", f.name, f.off, f.off+f.width, SignedSize)
		}
	}

	// The signed region ends exactly at the signature-usage field. SigUsage,
	// SigAlgo and A nonce are therefore *not* covered by the PEK signature, and
	// neither is anything after them. This is an ABI property, not an oversight:
	// callers must not treat those fields as authenticated on their own. The A
	// nonce in particular only unmasks other fields, and the values it produces
	// (user data, PEK certificate) are themselves checked downstream against the
	// peer certificate key and the trusted chain.
	if OffsetReportPolicy+4 != SignedSize {
		t.Fatalf("signed region ends at %#x, want SignedSize %#x", OffsetReportPolicy+4, SignedSize)
	}
	for _, f := range []struct {
		name string
		off  int
	}{
		{"sig usage", OffsetReportSigUsage},
		{"sig algo", OffsetReportSigAlgo},
		{"A nonce", OffsetANonce},
		{"PEK certificate", OffsetPEKCert},
		{"ChipID", OffsetChipID},
		{"MAC", OffsetMAC},
	} {
		if f.off < SignedSize {
			t.Errorf("%s at %#x must lie outside the signed region [0,%#x)", f.name, f.off, SignedSize)
		}
	}
	if OffsetReportSigUsage != SignedSize {
		t.Fatalf("OffsetReportSigUsage = %#x, want %#x", OffsetReportSigUsage, SignedSize)
	}

	// The A nonce sits immediately before the signature, and the signature
	// immediately before the PEK certificate.
	if OffsetANonce+4 != OffsetReportSig1 {
		t.Fatalf("A nonce must end at OffsetReportSig1: %#x+4 != %#x", OffsetANonce, OffsetReportSig1)
	}
	if OffsetReportSig1+144 != OffsetPEKCert {
		t.Fatalf("signature must end at OffsetPEKCert: %#x+144 != %#x", OffsetReportSig1, OffsetPEKCert)
	}

	// The region covered by the session MAC runs from the PEK certificate to the
	// MAC itself, with no gaps.
	if got := OffsetPEKCert + CSVCertSize; got != OffsetChipID {
		t.Fatalf("PEK cert ends at %#x, want OffsetChipID %#x", got, OffsetChipID)
	}
	if got := OffsetChipID + ChipIDSize; got != OffsetReserved2 {
		t.Fatalf("ChipID ends at %#x, want OffsetReserved2 %#x", got, OffsetReserved2)
	}
	if OffsetReserved2+SealingKeySize != OffsetMAC {
		t.Fatalf("reserved2 should end at MAC offset")
	}
	if OffsetPEKCert+CSVCertSize+ChipIDSize+SealingKeySize != OffsetMAC {
		t.Fatalf("session MAC input should end at MAC offset")
	}
	if OffsetMAC+HashSize != ReportSize {
		t.Fatalf("MAC ends at %#x, want ReportSize %#x", OffsetMAC+HashSize, ReportSize)
	}

	// The HSK/CEK bundle is the concatenation of a root certificate and a
	// service certificate, so it must be exactly twice the report's PEK size.
	if HskCekSize != HrkCertSize+CSVCertSize {
		t.Fatalf("HskCekSize = %#x, want %#x", HskCekSize, HrkCertSize+CSVCertSize)
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
