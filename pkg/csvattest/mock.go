package csvattest

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
)

// GenerateMockAttestationData produces a fully signed mock CSV attestation report
// and valid certificate chain (HRK -> HSK -> CEK -> PEK) suitable for testing.
func GenerateMockAttestationData(userData []byte, measurementHex string) (report []byte, hrkCert []byte, hskCekCert []byte, err error) {
	// 1. Generate keys
	hrkKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate hrk key: %w", err)
	}
	hskKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate hsk key: %w", err)
	}
	cekKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate cek key: %w", err)
	}
	pekKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate pek key: %w", err)
	}

	userID := []byte("test-sm2-user")

	// 2. Generate certificates
	// HRK cert (self-signed)
	hrkCert = make([]byte, HrkCertSize)
	binary.LittleEndian.PutUint32(hrkCert[OffsetRootKeyUsage:], KeyUsageHRK)
	putMockHygonPubKey(hrkCert[OffsetRootPubKey:], &hrkKey.PublicKey, userID)
	if err := signMockHygonData(hrkKey, hrkCert[:OffsetRootSig], hrkCert[OffsetRootSig:], userID); err != nil {
		return nil, nil, nil, fmt.Errorf("sign hrk cert: %w", err)
	}

	// HSK cert (signed by HRK)
	hskCert := make([]byte, HrkCertSize)
	binary.LittleEndian.PutUint32(hskCert[OffsetRootKeyUsage:], KeyUsageHSK)
	putMockHygonPubKey(hskCert[OffsetRootPubKey:], &hskKey.PublicKey, userID)
	if err := signMockHygonData(hrkKey, hskCert[:OffsetRootSig], hskCert[OffsetRootSig:], userID); err != nil {
		return nil, nil, nil, fmt.Errorf("sign hsk cert: %w", err)
	}

	// CEK cert (signed by HSK)
	cekCert := make([]byte, CSVCertSize)
	binary.LittleEndian.PutUint32(cekCert[OffsetCSVPubKeyUsage:], KeyUsageCEK)
	binary.LittleEndian.PutUint32(cekCert[OffsetCSVSig1Usage:], KeyUsageHSK)
	binary.LittleEndian.PutUint32(cekCert[OffsetCSVSig2Usage:], KeyUsageInvalid)
	putMockHygonPubKey(cekCert[OffsetCSVPubKey:], &cekKey.PublicKey, userID)
	if err := signMockHygonData(hskKey, cekCert[:OffsetCSVSig1Usage], cekCert[OffsetCSVSig1:], userID); err != nil {
		return nil, nil, nil, fmt.Errorf("sign cek cert: %w", err)
	}

	// PEK cert (signed by CEK)
	pekCert := make([]byte, CSVCertSize)
	binary.LittleEndian.PutUint32(pekCert[OffsetCSVPubKeyUsage:], KeyUsagePEK)
	binary.LittleEndian.PutUint32(pekCert[OffsetCSVSig1Usage:], KeyUsageCEK)
	binary.LittleEndian.PutUint32(pekCert[OffsetCSVSig2Usage:], KeyUsageInvalid)
	putMockHygonPubKey(pekCert[OffsetCSVPubKey:], &pekKey.PublicKey, userID)
	if err := signMockHygonData(cekKey, pekCert[:OffsetCSVSig1Usage], pekCert[OffsetCSVSig1:], userID); err != nil {
		return nil, nil, nil, fmt.Errorf("sign pek cert: %w", err)
	}

	hskCekCert = append(hskCert, cekCert...)

	// 3. Assemble report
	report = make([]byte, ReportSize)
	anonce := uint32(0)
	binary.LittleEndian.PutUint32(report[OffsetANonce:], anonce)

	// UserData (64 bytes)
	userBytes := make([]byte, UserDataSize)
	copy(userBytes, userData)
	copy(report[OffsetUserData:OffsetUserData+UserDataSize], UnmaskWords(userBytes, anonce))

	// MNonce (16 bytes)
	copy(report[OffsetMNonce:OffsetMNonce+NonceSize], UnmaskWords([]byte("0123456789abcdef"), anonce))

	// Measure (32 bytes)
	measureBytes, decErr := hex.DecodeString(measurementHex)
	if decErr != nil || len(measureBytes) != HashSize {
		measureBytes = bytes.Repeat([]byte{0x5A}, HashSize)
	}
	copy(report[OffsetMeasure:OffsetMeasure+HashSize], UnmaskWords(measureBytes, anonce))

	// PEK Cert
	copy(report[OffsetPEKCert:OffsetPEKCert+CSVCertSize], UnmaskWords(pekCert, anonce))

	// ChipID (64 bytes)
	chipID := append([]byte("TESTCHIP0001"), make([]byte, ChipIDSize-12)...)
	copy(report[OffsetChipID:OffsetChipID+ChipIDSize], UnmaskWords(chipID, anonce))

	// Sign report with PEK
	if err := signMockHygonData(pekKey, report[:SignedSize], report[OffsetReportSig1:], userID); err != nil {
		return nil, nil, nil, fmt.Errorf("sign report: %w", err)
	}

	return report, hrkCert, hskCekCert, nil
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
