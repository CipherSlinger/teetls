package csvattest

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestLoadCertChainFromFiles_Success(t *testing.T) {
	hrkPath := filepath.Join("..", "..", "deploy", "certs", "hrk.cert")
	hskCekPath := filepath.Join("..", "..", "deploy", "certs", "hsk_cek.cert")
	if _, err := os.Stat(hrkPath); err != nil {
		if _, errRoot := os.Stat("deploy/certs/hrk.cert"); errRoot == nil {
			hrkPath = "deploy/certs/hrk.cert"
			hskCekPath = "deploy/certs/hsk_cek.cert"
		} else {
			t.Skip("deploy/certs/hrk.cert not present, skipping real file test")
		}
	}

	chain, err := LoadCertChainFromFiles(hrkPath, hskCekPath)
	if err != nil {
		t.Fatalf("LoadCertChainFromFiles() error = %v", err)
	}
	if len(chain.HRK) != HrkCertSize {
		t.Errorf("len(chain.HRK) = %d, want %d", len(chain.HRK), HrkCertSize)
	}
	if len(chain.HSKCEK) != HskCekSize {
		t.Errorf("len(chain.HSKCEK) = %d, want %d", len(chain.HSKCEK), HskCekSize)
	}
	if chain.Source != "local file" {
		t.Errorf("chain.Source = %q, want %q", chain.Source, "local file")
	}
}

func TestLoadCertChainFromFiles_MissingFile(t *testing.T) {
	_, err := LoadCertChainFromFiles("/nonexistent/hrk.cert", "/nonexistent/hsk.cert")
	if err == nil {
		t.Fatal("LoadCertChainFromFiles() want error for nonexistent file, got nil")
	}
}

func TestVerifyReportWithOptions_CustomPaths(t *testing.T) {
	report, certs := newTestReport(t, true)
	dir := t.TempDir()
	hrkPath := filepath.Join(dir, "custom_hrk.cert")
	hskCekPath := filepath.Join(dir, "custom_hsk_cek.cert")

	if err := os.WriteFile(hrkPath, certs.hrk, 0o600); err != nil {
		t.Fatalf("failed to write custom hrk cert: %v", err)
	}
	hskCek := append(append([]byte(nil), certs.hsk...), certs.cek...)
	if err := os.WriteFile(hskCekPath, hskCek, 0o600); err != nil {
		t.Fatalf("failed to write custom hsk_cek cert: %v", err)
	}

	// 1. Success with explicit custom paths
	opts := VerifyOptions{
		VerifyChain:    true,
		HRKCertPath:    hrkPath,
		HSKCekCertPath: hskCekPath,
	}
	res, err := VerifyReportWithOptions(report, opts)
	if err != nil {
		t.Fatalf("VerifyReportWithOptions() with custom paths failed: %v", err)
	}
	if !res.ReportVerified {
		t.Errorf("res.ReportVerified = false, want true")
	}
	if !res.ChainVerified {
		t.Errorf("res.ChainVerified = false, want true")
	}
	if res.ChainSource != "local file" {
		t.Errorf("res.ChainSource = %q, want %q", res.ChainSource, "local file")
	}
	if res.CertDetails == nil {
		t.Errorf("res.CertDetails is nil, want populated details")
	}

	// 2. Failure with missing certificate files
	missingOpts := VerifyOptions{
		VerifyChain:    true,
		HRKCertPath:    filepath.Join(dir, "nonexistent_hrk.cert"),
		HSKCekCertPath: filepath.Join(dir, "nonexistent_hsk.cert"),
	}
	if _, err := VerifyReportWithOptions(report, missingOpts); err == nil {
		t.Fatal("VerifyReportWithOptions() want error for missing cert files, got nil")
	}

	// 3. VerifyChain = false skips chain verification
	noChainOpts := VerifyOptions{
		VerifyChain: false,
	}
	resNoChain, err := VerifyReportWithOptions(report, noChainOpts)
	if err != nil {
		t.Fatalf("VerifyReportWithOptions() with VerifyChain=false failed: %v", err)
	}
	if !resNoChain.ReportVerified {
		t.Errorf("resNoChain.ReportVerified = false, want true")
	}
	if resNoChain.ChainVerified {
		t.Errorf("resNoChain.ChainVerified = true, want false")
	}
}

func TestLoadLocalCertChain(t *testing.T) {
	dir := t.TempDir()
	hrkPath := filepath.Join(dir, "hrk.cert")
	hskCekPath := filepath.Join(dir, "hsk_cek.cert")

	if err := os.WriteFile(hrkPath, bytes.Repeat([]byte{1}, HrkCertSize), 0o600); err != nil {
		t.Fatalf("failed to write hrk: %v", err)
	}
	if err := os.WriteFile(hskCekPath, bytes.Repeat([]byte{2}, HskCekSize), 0o600); err != nil {
		t.Fatalf("failed to write hsk_cek: %v", err)
	}

	chain, err := LoadLocalCertChain(dir)
	if err != nil {
		t.Fatalf("LoadLocalCertChain() error = %v", err)
	}
	if chain.Source != "local file" {
		t.Errorf("chain.Source = %q, want %q", chain.Source, "local file")
	}
}

func TestVerifyReportData_Delegation(t *testing.T) {
	report, certs := newTestReport(t, true)
	dir := t.TempDir()
	hrkPath := filepath.Join(dir, "hrk.cert")
	hskCekPath := filepath.Join(dir, "hsk_cek.cert")

	if err := os.WriteFile(hrkPath, certs.hrk, 0o600); err != nil {
		t.Fatalf("failed to write hrk: %v", err)
	}
	hskCek := append(append([]byte(nil), certs.hsk...), certs.cek...)
	if err := os.WriteFile(hskCekPath, hskCek, 0o600); err != nil {
		t.Fatalf("failed to write hsk_cek: %v", err)
	}

	res, err := VerifyReportData(report, dir, true)
	if err != nil {
		t.Fatalf("VerifyReportData() failed: %v", err)
	}
	if !res.ReportVerified {
		t.Errorf("res.ReportVerified = false, want true")
	}
	if !res.ChainVerified {
		t.Errorf("res.ChainVerified = false, want true")
	}
}

func TestParseReport_ShortBuffer(t *testing.T) {
	_, err := ParseReport([]byte("short"))
	if err == nil {
		t.Fatal("ParseReport() want error for short buffer, got nil")
	}
}

func TestVerifyReportPEKSignature_Nil(t *testing.T) {
	if err := VerifyReportPEKSignature(nil); err == nil {
		t.Fatal("VerifyReportPEKSignature(nil) want error, got nil")
	}
}

type testAttestationCerts struct {
	hrk []byte
	hsk []byte
	cek []byte
}

func newTestSM2Key(t *testing.T) *sm2.PrivateKey {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate SM2 key pair: %v", err)
	}
	return key
}

func newTestRootCert(t *testing.T, key *sm2.PrivateKey, usage uint32, signer *sm2.PrivateKey) []byte {
	t.Helper()
	cert := make([]byte, HrkCertSize)
	binary.LittleEndian.PutUint32(cert[OffsetRootKeyUsage:], usage)
	putHygonPubKey(cert[OffsetRootPubKey:], &key.PublicKey, []byte("test-sm2-user"))
	signHygonData(t, signer, cert[:OffsetRootSig], cert[OffsetRootSig:])
	return cert
}

func newTestCSVCert(t *testing.T, key *sm2.PrivateKey, usage uint32) []byte {
	t.Helper()
	cert := make([]byte, CSVCertSize)
	binary.LittleEndian.PutUint32(cert[OffsetCSVPubKeyUsage:], usage)
	binary.LittleEndian.PutUint32(cert[OffsetCSVSig1Usage:], KeyUsageInvalid)
	binary.LittleEndian.PutUint32(cert[OffsetCSVSig2Usage:], KeyUsageInvalid)
	putHygonPubKey(cert[OffsetCSVPubKey:], &key.PublicKey, []byte("test-sm2-user"))
	return cert
}

func signHygonData(t *testing.T, key *sm2.PrivateKey, msg []byte, sig []byte) {
	t.Helper()
	r, s, err := sm2.Sm2Sign(key, msg, []byte("test-sm2-user"), rand.Reader)
	if err != nil {
		t.Fatalf("failed to sign SM2 data: %v", err)
	}
	copy(sig[OffsetHygonSigR:OffsetHygonSigR+32], ReverseCopy(leftPad32(r.Bytes())))
	copy(sig[OffsetHygonSigS:OffsetHygonSigS+32], ReverseCopy(leftPad32(s.Bytes())))
}

func putHygonPubKey(dst []byte, pub *sm2.PublicKey, userID []byte) {
	binary.LittleEndian.PutUint32(dst, CurveIDSM2)
	copy(dst[OffsetECCPubKeyQX:OffsetECCPubKeyQX+32], ReverseCopy(leftPad32(pub.X.Bytes())))
	copy(dst[OffsetECCPubKeyQY:OffsetECCPubKeyQY+32], ReverseCopy(leftPad32(pub.Y.Bytes())))
	binary.LittleEndian.PutUint16(dst[OffsetECCPubKeyUserID:], uint16(len(userID)))
	copy(dst[OffsetECCPubKeyUserID+2:], userID)
}

func leftPad32(in []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(in):], in)
	return out
}

func newTestReport(t *testing.T, withChain bool) ([]byte, *testAttestationCerts) {
	t.Helper()
	pek := newTestSM2Key(t)
	pekCert := newTestCSVCert(t, pek, KeyUsagePEK)

	var certs *testAttestationCerts
	if withChain {
		hrk := newTestSM2Key(t)
		hsk := newTestSM2Key(t)
		cek := newTestSM2Key(t)
		hrkCert := newTestRootCert(t, hrk, KeyUsageHRK, hrk)
		hskCert := newTestRootCert(t, hsk, KeyUsageHSK, hrk)
		cekCert := newTestCSVCert(t, cek, KeyUsageCEK)
		binary.LittleEndian.PutUint32(cekCert[OffsetCSVSig1Usage:], KeyUsageHSK)
		binary.LittleEndian.PutUint32(cekCert[OffsetCSVSig2Usage:], KeyUsageInvalid)
		signHygonData(t, hsk, cekCert[:OffsetCSVSig1Usage], cekCert[OffsetCSVSig1:])
		binary.LittleEndian.PutUint32(pekCert[OffsetCSVSig1Usage:], KeyUsageCEK)
		signHygonData(t, cek, pekCert[:OffsetCSVSig1Usage], pekCert[OffsetCSVSig1:])
		certs = &testAttestationCerts{hrk: hrkCert, hsk: hskCert, cek: cekCert}
	}

	report := make([]byte, ReportSize)
	anonce := uint32(0x11223344)
	binary.LittleEndian.PutUint32(report[OffsetANonce:], anonce)
	copy(report[OffsetUserData:OffsetUserData+64], UnmaskWords(bytes.Repeat([]byte{0xA5}, 64), anonce))
	copy(report[OffsetMNonce:OffsetMNonce+16], UnmaskWords([]byte("0123456789abcdef"), anonce))
	copy(report[OffsetMeasure:OffsetMeasure+32], UnmaskWords(bytes.Repeat([]byte{0x5A}, 32), anonce))
	copy(report[OffsetPEKCert:OffsetPEKCert+CSVCertSize], UnmaskWords(pekCert, anonce))
	copy(report[OffsetChipID:OffsetChipID+64], UnmaskWords(append([]byte("TESTCHIP0001"), make([]byte, 52)...), anonce))
	signHygonData(t, pek, report[:SignedSize], report[OffsetReportSig1:])
	return report, certs
}
