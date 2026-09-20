package csvattest

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/tjfoc/gmsm/sm2"
)

// MockAttestationAuthority owns a mock HRK -> HSK -> CEK -> PEK chain for tests.
type MockAttestationAuthority struct {
	mu sync.Mutex

	hrkKey *sm2.PrivateKey
	hskKey *sm2.PrivateKey
	cekKey *sm2.PrivateKey
	pekKey *sm2.PrivateKey
	userID []byte

	hrkCert    []byte
	hskCekCert []byte
	pekCert    []byte
}

// NewMockAttestationAuthority creates a reusable mock attestation authority.
func NewMockAttestationAuthority() (*MockAttestationAuthority, error) {
	hrkKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate hrk key: %w", err)
	}
	hskKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate hsk key: %w", err)
	}
	cekKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate cek key: %w", err)
	}
	pekKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate pek key: %w", err)
	}

	a := &MockAttestationAuthority{
		hrkKey: hrkKey,
		hskKey: hskKey,
		cekKey: cekKey,
		pekKey: pekKey,
		userID: []byte("test-sm2-user"),
	}
	if err := a.generateCertificates(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *MockAttestationAuthority) generateCertificates() error {
	// HRK cert (self-signed)
	a.hrkCert = make([]byte, HrkCertSize)
	binary.LittleEndian.PutUint32(a.hrkCert[OffsetRootKeyUsage:], KeyUsageHRK)
	putMockHygonPubKey(a.hrkCert[OffsetRootPubKey:], &a.hrkKey.PublicKey, a.userID)
	if err := signMockHygonData(a.hrkKey, a.hrkCert[:OffsetRootSig], a.hrkCert[OffsetRootSig:], a.userID); err != nil {
		return fmt.Errorf("sign hrk cert: %w", err)
	}

	// HSK cert (signed by HRK)
	hskCert := make([]byte, HrkCertSize)
	binary.LittleEndian.PutUint32(hskCert[OffsetRootKeyUsage:], KeyUsageHSK)
	putMockHygonPubKey(hskCert[OffsetRootPubKey:], &a.hskKey.PublicKey, a.userID)
	if err := signMockHygonData(a.hrkKey, hskCert[:OffsetRootSig], hskCert[OffsetRootSig:], a.userID); err != nil {
		return fmt.Errorf("sign hsk cert: %w", err)
	}

	// CEK cert (signed by HSK)
	cekCert := make([]byte, CSVCertSize)
	binary.LittleEndian.PutUint32(cekCert[OffsetCSVPubKeyUsage:], KeyUsageCEK)
	binary.LittleEndian.PutUint32(cekCert[OffsetCSVSig1Usage:], KeyUsageHSK)
	binary.LittleEndian.PutUint32(cekCert[OffsetCSVSig2Usage:], KeyUsageInvalid)
	putMockHygonPubKey(cekCert[OffsetCSVPubKey:], &a.cekKey.PublicKey, a.userID)
	if err := signMockHygonData(a.hskKey, cekCert[:OffsetCSVSig1Usage], cekCert[OffsetCSVSig1:], a.userID); err != nil {
		return fmt.Errorf("sign cek cert: %w", err)
	}

	// PEK cert (signed by CEK)
	a.pekCert = make([]byte, CSVCertSize)
	binary.LittleEndian.PutUint32(a.pekCert[OffsetCSVPubKeyUsage:], KeyUsagePEK)
	binary.LittleEndian.PutUint32(a.pekCert[OffsetCSVSig1Usage:], KeyUsageCEK)
	binary.LittleEndian.PutUint32(a.pekCert[OffsetCSVSig2Usage:], KeyUsageInvalid)
	putMockHygonPubKey(a.pekCert[OffsetCSVPubKey:], &a.pekKey.PublicKey, a.userID)
	if err := signMockHygonData(a.cekKey, a.pekCert[:OffsetCSVSig1Usage], a.pekCert[OffsetCSVSig1:], a.userID); err != nil {
		return fmt.Errorf("sign pek cert: %w", err)
	}

	a.hskCekCert = append(hskCert, cekCert...)
	return nil
}

// HRKCert returns a copy of the mock trusted HRK certificate.
func (a *MockAttestationAuthority) HRKCert() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.hrkCert...)
}

// HSKCekCert returns a copy of the mock HSK/CEK certificate bundle.
func (a *MockAttestationAuthority) HSKCekCert() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.hskCekCert...)
}

// Generate produces a signed mock CSV attestation report using this authority.
func (a *MockAttestationAuthority) Generate(userData []byte, measurementHex string) (report []byte, hrkCert []byte, hskCekCert []byte, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Assemble report.
	report = make([]byte, ReportSize)
	anonce := uint32(0)
	binary.LittleEndian.PutUint32(report[OffsetANonce:], anonce)

	userBytes := make([]byte, UserDataSize)
	copy(userBytes, userData)
	copy(report[OffsetUserData:OffsetUserData+UserDataSize], UnmaskWords(userBytes, anonce))

	copy(report[OffsetMNonce:OffsetMNonce+NonceSize], UnmaskWords([]byte("0123456789abcdef"), anonce))

	measureBytes, decErr := hex.DecodeString(measurementHex)
	if decErr != nil || len(measureBytes) != HashSize {
		measureBytes = bytes.Repeat([]byte{0x5A}, HashSize)
	}
	copy(report[OffsetMeasure:OffsetMeasure+HashSize], UnmaskWords(measureBytes, anonce))

	copy(report[OffsetPEKCert:OffsetPEKCert+CSVCertSize], UnmaskWords(a.pekCert, anonce))

	chipID := append([]byte("TESTCHIP0001"), make([]byte, ChipIDSize-12)...)
	copy(report[OffsetChipID:OffsetChipID+ChipIDSize], UnmaskWords(chipID, anonce))

	if err := signMockHygonData(a.pekKey, report[:SignedSize], report[OffsetReportSig1:], a.userID); err != nil {
		return nil, nil, nil, fmt.Errorf("sign report: %w", err)
	}

	return report, append([]byte(nil), a.hrkCert...), append([]byte(nil), a.hskCekCert...), nil
}

// GenerateMockAttestationData produces a fully signed mock CSV attestation report
// and valid certificate chain (HRK -> HSK -> CEK -> PEK) suitable for testing.
func GenerateMockAttestationData(userData []byte, measurementHex string) (report []byte, hrkCert []byte, hskCekCert []byte, err error) {
	a, err := NewMockAttestationAuthority()
	if err != nil {
		return nil, nil, nil, err
	}
	return a.Generate(userData, measurementHex)
}

func putMockHygonPubKey(dst []byte, pub *sm2.PublicKey, userID []byte) {
	binary.LittleEndian.PutUint32(dst, CurveIDSM2)
	copy(dst[OffsetECCPubKeyQX:OffsetECCPubKeyQX+32], ReverseCopy(padLeft32(pub.X.Bytes())))
	copy(dst[OffsetECCPubKeyQY:OffsetECCPubKeyQY+32], ReverseCopy(padLeft32(pub.Y.Bytes())))
	binary.LittleEndian.PutUint16(dst[OffsetECCPubKeyUserID:], uint16(len(userID)))
	copy(dst[OffsetECCPubKeyUserID+2:], userID)
}

func signMockHygonData(key *sm2.PrivateKey, msg, sig, userID []byte) error {
	r, s, err := sm2.Sm2Sign(key, msg, userID, rand.Reader)
	if err != nil {
		return err
	}
	copy(sig[OffsetHygonSigR:OffsetHygonSigR+32], ReverseCopy(padLeft32(r.Bytes())))
	copy(sig[OffsetHygonSigS:OffsetHygonSigS+32], ReverseCopy(padLeft32(s.Bytes())))
	return nil
}

func padLeft32(in []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(in):], in)
	return out
}
