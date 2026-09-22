package csvattest

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestLoadCertChainFromFiles_Success(t *testing.T) {
	// Build the chain in a temporary directory rather than depending on
	// deploy/certs, which is not part of the repository, so that the real
	// file-loading path is exercised instead of skipped.
	report, certs := newTestReport(t, true)
	if len(report) != ReportSize {
		t.Fatalf("test fixture report is %d bytes, want %d", len(report), ReportSize)
	}

	dir := t.TempDir()
	hrkPath := filepath.Join(dir, "hrk.cert")
	hskCekPath := filepath.Join(dir, "hsk_cek.cert")

	if err := os.WriteFile(hrkPath, certs.hrk, 0o600); err != nil {
		t.Fatalf("write hrk cert: %v", err)
	}
	hskCek := append(append([]byte(nil), certs.hsk...), certs.cek...)
	if err := os.WriteFile(hskCekPath, hskCek, 0o600); err != nil {
		t.Fatalf("write hsk_cek cert: %v", err)
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

// TestLoadCertChainFromFiles_NormalisesTrailingBytes verifies that a trailing
// newline, which is what a plain file read of a provisioned certificate usually
// leaves behind, does not change the loaded material.
func TestLoadCertChainFromFiles_NormalisesTrailingBytes(t *testing.T) {
	_, certs := newTestReport(t, true)

	dir := t.TempDir()
	hrkPath := filepath.Join(dir, "hrk.cert")
	hskCekPath := filepath.Join(dir, "hsk_cek.cert")

	if err := os.WriteFile(hrkPath, append(append([]byte(nil), certs.hrk...), '\n'), 0o600); err != nil {
		t.Fatalf("write hrk cert: %v", err)
	}
	hskCek := append(append(append([]byte(nil), certs.hsk...), certs.cek...), '\n')
	if err := os.WriteFile(hskCekPath, hskCek, 0o600); err != nil {
		t.Fatalf("write hsk_cek cert: %v", err)
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
	if !bytes.Equal(chain.HRK, certs.hrk) {
		t.Error("loaded HRK differs from the certificate on disk")
	}
}

// TestLoadCertChainFromFiles_ShortFile verifies that a truncated certificate is
// rejected rather than silently accepted with a short length.
func TestLoadCertChainFromFiles_ShortFile(t *testing.T) {
	_, certs := newTestReport(t, true)

	dir := t.TempDir()
	hrkPath := filepath.Join(dir, "hrk.cert")
	hskCekPath := filepath.Join(dir, "hsk_cek.cert")

	if err := os.WriteFile(hrkPath, certs.hrk[:HrkCertSize-1], 0o600); err != nil {
		t.Fatalf("write short hrk cert: %v", err)
	}
	hskCek := append(append([]byte(nil), certs.hsk...), certs.cek...)
	if err := os.WriteFile(hskCekPath, hskCek, 0o600); err != nil {
		t.Fatalf("write hsk_cek cert: %v", err)
	}

	if _, err := LoadCertChainFromFiles(hrkPath, hskCekPath); err == nil {
		t.Fatal("LoadCertChainFromFiles() accepted a truncated HRK certificate")
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

// TestVerifyReportPEKSignature_RejectsShortFields checks that a caller-built
// VerificationResult with a truncated PEK certificate or report signature is
// rejected with an error instead of panicking on a slice expression.
func TestVerifyReportPEKSignature_RejectsShortFields(t *testing.T) {
	// Parse a genuine report so the PEK certificate is a real one: without that,
	// the short-Signature case would be masked by a public-key parse failure and
	// would pass for the wrong reason.
	full, err := ParseReport(mustTestReport(t, false))
	if err != nil {
		t.Fatalf("ParseReport() error = %v", err)
	}
	if err := VerifyReportPEKSignature(full); err != nil {
		t.Fatalf("VerifyReportPEKSignature(valid report) error = %v, want nil", err)
	}

	cases := []struct {
		name   string
		mutate func(*VerificationResult)
	}{
		{"nil PEKCert", func(r *VerificationResult) { r.PEKCert = nil }},
		{"short PEKCert", func(r *VerificationResult) { r.PEKCert = r.PEKCert[:4] }},
		{"PEKCert one byte short", func(r *VerificationResult) { r.PEKCert = r.PEKCert[:CSVCertSize-1] }},
		{"nil Signature", func(r *VerificationResult) { r.Signature = nil }},
		{"short Signature", func(r *VerificationResult) { r.Signature = make([]byte, OffsetHygonSigS+31) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := *full
			tc.mutate(&res)
			err := VerifyReportPEKSignature(&res)
			if !errors.Is(err, ErrShortBuffer) {
				t.Fatalf("VerifyReportPEKSignature(%s) error = %v, want ErrShortBuffer", tc.name, err)
			}
		})
	}
}

// TestParseHygonSignature_ShortBuffer pins the fail-closed contract of the
// exported parser: a short buffer yields zero values, and zero values cannot
// satisfy sm2.Sm2Verify's requirement that r and s lie in [1, N-1].
func TestParseHygonSignature_ShortBuffer(t *testing.T) {
	for _, n := range []int{0, 1, 64, OffsetHygonSigS + 31} {
		r, s := ParseHygonSignature(make([]byte, n))
		if r.Sign() != 0 || s.Sign() != 0 {
			t.Fatalf("ParseHygonSignature(len=%d) = (%v, %v), want (0, 0)", n, r, s)
		}
	}

	// The minimum accepted length must still parse r and s as distinct halves.
	sig := make([]byte, OffsetHygonSigS+32)
	sig[0] = 1 // r = 1
	sig[OffsetHygonSigS] = 2
	r, s := ParseHygonSignature(sig)
	if r.Int64() != 1 || s.Int64() != 2 {
		t.Fatalf("ParseHygonSignature(minimum length) = (%v, %v), want (1, 2)", r, s)
	}

	// Zero r and s are rejected by the verifier, which is what makes the
	// short-buffer branch fail closed rather than accept.
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	if sm2.Sm2Verify(&key.PublicKey, []byte("msg"), nil, r, s) {
		t.Fatal("sm2.Sm2Verify accepted r=1, s=2")
	}
	zero := new(big.Int)
	if sm2.Sm2Verify(&key.PublicKey, []byte("msg"), nil, zero, zero) {
		t.Fatal("sm2.Sm2Verify accepted (0, 0)")
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

// mustTestReport returns only the report from newTestReport, for tests that do
// not need the certificate chain.
func mustTestReport(t *testing.T, withChain bool) []byte {
	t.Helper()
	report, _ := newTestReport(t, withChain)
	return report
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
