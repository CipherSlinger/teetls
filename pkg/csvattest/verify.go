package csvattest

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/tjfoc/gmsm/sm2"
)

var (
	// ErrMissingCertChain indicates that chain verification was requested without local chain material.
	ErrMissingCertChain = errors.New("missing CSV certificate chain")
	// ErrUntrustedHRK indicates that peer HRK material does not match the trusted HRK anchor.
	ErrUntrustedHRK = errors.New("untrusted HRK certificate")
)

type VerificationResult struct {
	ReportSize     int
	PubkeyDigest   []byte
	VMID           []byte
	VMVersion      []byte
	UserData       []byte
	MNonce         []byte
	Digest         []byte
	Policy         uint32
	SigUsage       uint32
	SigAlgo        uint32
	ANonce         uint32
	Signature      []byte
	PEKCert        []byte
	ChipID         []byte
	ChipIDASCII    string
	Reserved2      []byte
	MAC            []byte
	PEKDetails     CSVCertDetails
	ReportVerified bool
	ChainVerified  bool
	ChainSource    string
	// HRKURL and HSKCEKURL are informational: they record where the chain
	// material for this chip would be published, for out-of-band provisioning.
	// Verification never fetches them.
	HRKURL      string
	HSKCEKURL   string
	CertDetails *CertChainDetails
	rawReport   []byte
}

type PubKeyDetails struct {
	CurveID   uint32
	UserID    string
	UserIDHex string
	QXHex     string
	QYHex     string
}

type RootCertDetails struct {
	KeyUsage              uint32
	PubKey                PubKeyDetails
	SelfSignatureVerified bool
	SignedByHRKVerified   bool
}

type CSVCertDetails struct {
	PubKeyUsage         uint32
	Sig1Usage           uint32
	Sig2Usage           uint32
	PubKey              PubKeyDetails
	SignedByHSKVerified bool
	SignedByCEKVerified bool
}

type CertChainDetails struct {
	HRK RootCertDetails
	HSK RootCertDetails
	CEK CSVCertDetails
	PEK CSVCertDetails
}

type CertChainInput struct {
	HRK    []byte
	HSKCEK []byte
	// Source describes where the chain material was read from, for diagnostics.
	Source string
}

func (c *Client) VerifyAttestationReport(reportBuf []byte, verifyChain bool) error {
	_, err := VerifyReportData(reportBuf, ".", verifyChain)
	return err
}

func VerifyReport(reportFile string, verifyChain bool) (*VerificationResult, error) {
	reportFile = strings.TrimSpace(reportFile)
	if reportFile == "" {
		return nil, errors.New("report file path cannot be empty")
	}
	data, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, fmt.Errorf("read report file: %w", err)
	}
	return VerifyReportData(data, filepath.Dir(reportFile), verifyChain)
}

// VerifyOptions controls attestation verification options including explicit cert paths.
type VerifyOptions struct {
	VerifyChain bool

	// TrustedHRKCertBytes and TrustedHRKCertPath identify the local HRK trust anchor.
	TrustedHRKCertBytes []byte
	TrustedHRKCertPath  string

	// HSKCekCertBytes and HSKCekCertPath identify the HSK/CEK intermediate bundle.
	HSKCekCertBytes []byte
	HSKCekCertPath  string

	// CertDir specifies a local directory containing hrk.cert and hsk_cek.cert.
	CertDir string

	// HRKCertBytes and HRKCertPath are deprecated aliases for trusted HRK input.
	HRKCertBytes []byte
	HRKCertPath  string
}

// ParseReport parses an attestation report buffer into a VerificationResult.
func ParseReport(data []byte) (*VerificationResult, error) {
	if len(data) < ReportSize {
		return nil, fmt.Errorf("%w: report has %d bytes, need %d", ErrShortBuffer, len(data), ReportSize)
	}
	report := data[:ReportSize]
	anonce := binary.LittleEndian.Uint32(report[OffsetANonce : OffsetANonce+4])

	pubkeyDigest := append([]byte(nil), report[OffsetReportPubkeyDigest:OffsetReportPubkeyDigest+HashSize]...)
	vmID := append([]byte(nil), report[OffsetReportVMID:OffsetReportVMID+16]...)
	vmVersion := append([]byte(nil), report[OffsetReportVMVersion:OffsetReportVMVersion+16]...)
	signature := append([]byte(nil), report[OffsetReportSig1:OffsetReportSig1+144]...)
	reserved2 := append([]byte(nil), report[OffsetReserved2:OffsetReserved2+SealingKeySize]...)
	mac := append([]byte(nil), report[OffsetMAC:OffsetMAC+HashSize]...)

	userData := UnmaskWords(report[OffsetUserData:OffsetUserData+UserDataSize], anonce)
	mnonce := UnmaskWords(report[OffsetMNonce:OffsetMNonce+NonceSize], anonce)
	digest := UnmaskWords(report[OffsetMeasure:OffsetMeasure+HashSize], anonce)
	chipID := UnmaskWords(report[OffsetChipID:OffsetChipID+ChipIDSize], anonce)
	pekCert := UnmaskWords(report[OffsetPEKCert:OffsetPEKCert+CSVCertSize], anonce)

	policy := binary.LittleEndian.Uint32(UnmaskWords(report[OffsetReportPolicy:OffsetReportPolicy+4], anonce))
	sigUsage := binary.LittleEndian.Uint32(UnmaskWords(report[OffsetReportSigUsage:OffsetReportSigUsage+4], anonce))
	sigAlgo := binary.LittleEndian.Uint32(UnmaskWords(report[OffsetReportSigAlgo:OffsetReportSigAlgo+4], anonce))

	result := &VerificationResult{
		ReportSize:   len(report),
		PubkeyDigest: pubkeyDigest,
		VMID:         vmID,
		VMVersion:    vmVersion,
		UserData:     userData,
		MNonce:       mnonce,
		Digest:       digest,
		Policy:       policy,
		SigUsage:     sigUsage,
		SigAlgo:      sigAlgo,
		ANonce:       anonce,
		Signature:    signature,
		PEKCert:      pekCert,
		ChipID:       chipID,
		Reserved2:    reserved2,
		MAC:          mac,
		HRKURL:       HRKCertURL,
		rawReport:    append([]byte(nil), report...),
	}

	chipIDASCII, err := ChipIDASCII(result.ChipID)
	if err != nil {
		return result, fmt.Errorf("failed to parse ChipID: %w", err)
	}
	result.ChipIDASCII = chipIDASCII
	result.HSKCEKURL = KDSCertURL + url.QueryEscape(chipIDASCII)

	pekDetails, err := ParseCSVCertDetails(pekCert)
	if err != nil {
		return result, fmt.Errorf("failed to parse PEK certificate from report: %w", err)
	}
	result.PEKDetails = pekDetails

	return result, nil
}

// VerifyReportPEKSignature verifies the PEK signature on the report header.
func VerifyReportPEKSignature(res *VerificationResult) error {
	if res == nil {
		return errors.New("verification result is nil")
	}
	// VerificationResult is exported and its fields are settable, and this
	// exported entry point is documented as taking one, so a caller can build a
	// result directly. Every field sliced below is therefore length-checked
	// first: without these checks a short PEKCert panics on the slice expression
	// and a short Signature panics inside ParseHygonSignature, turning a caller
	// mistake into a crash. Requiring the full CSVCertSize rather than the 16
	// bytes the slice itself needs also covers the reads parseHygonPubKey
	// performs inside the certificate, and ParseReport always supplies exactly
	// that many bytes.
	if len(res.PEKCert) < CSVCertSize {
		return fmt.Errorf("%w: PEK certificate is %d bytes, need %d", ErrShortBuffer, len(res.PEKCert), CSVCertSize)
	}
	if len(res.Signature) < OffsetHygonSigS+32 {
		return fmt.Errorf("%w: report signature is %d bytes, need %d", ErrShortBuffer, len(res.Signature), OffsetHygonSigS+32)
	}
	pekPub, err := parseHygonPubKey(res.PEKCert[OffsetCSVPubKey:])
	if err != nil {
		return fmt.Errorf("failed to parse PEK public key from report: %w", err)
	}

	// The PEK signature covers exactly the first SignedSize bytes of the report
	// as they appear on the wire, i.e. with the masked fields still masked.
	// ParseReport always materialises a full ReportSize buffer, which is larger
	// than SignedSize, so the raw bytes are always available.
	//
	// The signed region stops at OffsetReportSigUsage, so SigUsage, SigAlgo, the
	// A nonce, the PEK certificate, the ChipID and the MAC are not covered by it.
	// That is the hardware ABI and not something this layer can change: the A
	// nonce is only an unmasking key, and every value it unmasks that matters
	// here is checked independently downstream (USER_DATA against the peer
	// public key, the PEK certificate against the trusted chain). Callers must
	// not rely on those fields being authenticated.
	if len(res.rawReport) < SignedSize {
		return fmt.Errorf("%w: report is %d bytes, need at least %d", ErrShortBuffer, len(res.rawReport), SignedSize)
	}
	signed := res.rawReport[:SignedSize]

	r, s := ParseHygonSignature(res.Signature)
	if !sm2.Sm2Verify(pekPub.Key, signed, pekPub.UserID, r, s) {
		return errors.New("PEK report signature verification failed")
	}
	res.ReportVerified = true
	return nil
}

var loadCertChain = LoadCertChain

// VerifyReportWithOptions verifies an attestation report using the provided options.
func VerifyReportWithOptions(data []byte, opts VerifyOptions) (*VerificationResult, error) {
	res, err := ParseReport(data)
	if err != nil {
		return res, err
	}

	if err := VerifyReportPEKSignature(res); err != nil {
		return res, err
	}

	if !opts.VerifyChain {
		return res, nil
	}

	certs, err := loadChainFromOptions(opts, res.ChipIDASCII)
	if err != nil {
		return res, err
	}

	res.ChainSource = certs.Source

	details, err := VerifyCertChain(certs, res.PEKCert)
	if details != nil {
		res.CertDetails = details
		res.PEKDetails = details.PEK
	}
	if err != nil {
		return res, err
	}
	res.ChainVerified = true
	return res, nil
}

// VerifyReportData verifies an attestation report using a certificate directory.
func VerifyReportData(data []byte, certDir string, verifyChain bool) (*VerificationResult, error) {
	return VerifyReportWithOptions(data, VerifyOptions{
		VerifyChain: verifyChain,
		CertDir:     certDir,
	})
}

func loadChainFromOptions(opts VerifyOptions, chipIDASCII string) (*CertChainInput, error) {
	trustedHRK := opts.TrustedHRKCertBytes
	if len(trustedHRK) == 0 {
		trustedHRK = opts.HRKCertBytes
	}
	trustedHRKPath := strings.TrimSpace(opts.TrustedHRKCertPath)
	if trustedHRKPath == "" {
		trustedHRKPath = strings.TrimSpace(opts.HRKCertPath)
	}
	hskCek := opts.HSKCekCertBytes
	hskCekPath := strings.TrimSpace(opts.HSKCekCertPath)

	if len(trustedHRK) > 0 || len(hskCek) > 0 {
		if len(trustedHRK) == 0 || len(hskCek) == 0 {
			return nil, fmt.Errorf("%w: trusted HRK and HSK/CEK bytes must be provided together", ErrMissingCertChain)
		}
		return &CertChainInput{
			HRK:    append([]byte(nil), trustedHRK...),
			HSKCEK: append([]byte(nil), hskCek...),
			Source: "in-memory trusted HRK and HSK/CEK bytes",
		}, nil
	}

	if trustedHRKPath != "" || hskCekPath != "" {
		if trustedHRKPath == "" || hskCekPath == "" {
			return nil, fmt.Errorf("%w: trusted HRK and HSK/CEK paths must be provided together", ErrMissingCertChain)
		}
		return LoadCertChainFromFiles(trustedHRKPath, hskCekPath)
	}

	if strings.TrimSpace(opts.CertDir) != "" {
		return loadCertChain(opts.CertDir, chipIDASCII)
	}

	return nil, fmt.Errorf("%w: no trusted HRK and HSK/CEK material configured", ErrMissingCertChain)
}

// LoadCertChainFromFiles loads HRK and HSK/CEK certificates from explicit file paths.
func LoadCertChainFromFiles(hrkPath, hskCekPath string) (*CertChainInput, error) {
	hrk, err := readFixedFile(hrkPath, HrkCertSize)
	if err != nil {
		return nil, fmt.Errorf("read hrk cert %s: %w", hrkPath, err)
	}
	hskCek, err := readFixedFile(hskCekPath, HskCekSize)
	if err != nil {
		return nil, fmt.Errorf("read hsk_cek cert %s: %w", hskCekPath, err)
	}
	return &CertChainInput{HRK: hrk, HSKCEK: hskCek, Source: "local file"}, nil
}

func LoadCertChain(certDir string, chipIDASCII string) (*CertChainInput, error) {
	local, err := LoadLocalCertChain(certDir)
	if err != nil {
		return nil, fmt.Errorf("%w: local certificates unavailable (chip_id=%s): %v", ErrMissingCertChain, chipIDASCII, err)
	}
	return local, nil
}

// LoadLocalCertChain loads certificates from a directory containing hrk.cert and hsk_cek.cert.
func LoadLocalCertChain(certDir string) (*CertChainInput, error) {
	return LoadCertChainFromFiles(filepath.Join(certDir, "hrk.cert"), filepath.Join(certDir, "hsk_cek.cert"))
}

func VerifyCertChain(certs *CertChainInput, pekCert []byte) (*CertChainDetails, error) {
	if len(certs.HRK) < HrkCertSize {
		return nil, fmt.Errorf("hrk.cert is %d bytes, need at least %d", len(certs.HRK), HrkCertSize)
	}
	if len(certs.HSKCEK) < HskCekSize {
		return nil, fmt.Errorf("hsk_cek.cert is %d bytes, need at least %d", len(certs.HSKCEK), HskCekSize)
	}
	hrk := certs.HRK[:HrkCertSize]
	hsk := certs.HSKCEK[:HrkCertSize]
	cek := certs.HSKCEK[HrkCertSize:HskCekSize]

	details := &CertChainDetails{}
	var err error
	details.HRK, err = ParseRootCertDetails(hrk)
	if err != nil {
		return details, fmt.Errorf("parse HRK cert: %w", err)
	}
	details.HSK, err = ParseRootCertDetails(hsk)
	if err != nil {
		return details, fmt.Errorf("parse HSK cert: %w", err)
	}
	details.CEK, err = ParseCSVCertDetails(cek)
	if err != nil {
		return details, fmt.Errorf("parse CEK cert: %w", err)
	}
	details.PEK, err = ParseCSVCertDetails(pekCert)
	if err != nil {
		return details, fmt.Errorf("parse PEK cert: %w", err)
	}

	if details.HRK.KeyUsage != KeyUsageHRK {
		return details, fmt.Errorf("invalid HRK key_usage: 0x%x", details.HRK.KeyUsage)
	}
	if details.HSK.KeyUsage != KeyUsageHSK {
		return details, fmt.Errorf("invalid HSK key_usage: 0x%x", details.HSK.KeyUsage)
	}
	if details.CEK.PubKeyUsage != KeyUsageCEK {
		return details, fmt.Errorf("invalid CEK pubkey_usage: 0x%x", details.CEK.PubKeyUsage)
	}
	if details.CEK.Sig1Usage != KeyUsageHSK {
		return details, fmt.Errorf("invalid CEK sig1_usage: 0x%x", details.CEK.Sig1Usage)
	}
	if details.CEK.Sig2Usage != KeyUsageInvalid {
		return details, fmt.Errorf("invalid CEK sig2_usage: 0x%x", details.CEK.Sig2Usage)
	}
	if details.PEK.PubKeyUsage != KeyUsagePEK {
		return details, fmt.Errorf("invalid PEK pubkey_usage: 0x%x", details.PEK.PubKeyUsage)
	}

	hrkPub, err := parseHygonPubKey(hrk[OffsetRootPubKey:])
	if err != nil {
		return details, fmt.Errorf("parse HRK public key: %w", err)
	}
	hskPub, err := parseHygonPubKey(hsk[OffsetRootPubKey:])
	if err != nil {
		return details, fmt.Errorf("parse HSK public key: %w", err)
	}
	cekPub, err := parseHygonPubKey(cek[OffsetCSVPubKey:])
	if err != nil {
		return details, fmt.Errorf("parse CEK public key: %w", err)
	}

	details.HRK.SelfSignatureVerified = verifyHygonSignature(hrkPub, hrk[:OffsetRootSig], hrk[OffsetRootSig:])
	if !details.HRK.SelfSignatureVerified {
		return details, errors.New("HRK self-signature verification failed")
	}
	details.HSK.SignedByHRKVerified = verifyHygonSignature(hrkPub, hsk[:OffsetRootSig], hsk[OffsetRootSig:])
	if !details.HSK.SignedByHRKVerified {
		return details, errors.New("HRK verification of HSK signature failed")
	}
	details.CEK.SignedByHSKVerified = verifyHygonSignature(hskPub, cek[:OffsetCSVSig1Usage], cek[OffsetCSVSig1:])
	if !details.CEK.SignedByHSKVerified {
		return details, errors.New("HSK verification of CEK signature failed")
	}
	details.PEK.SignedByCEKVerified = verifyHygonSignature(cekPub, pekCert[:OffsetCSVSig1Usage], pekCert[OffsetCSVSig1:])
	if !details.PEK.SignedByCEKVerified {
		return details, errors.New("CEK verification of PEK signature failed")
	}
	return details, nil
}

type hygonPubKey struct {
	Key     *sm2.PublicKey
	UserID  []byte
	Details PubKeyDetails
}

func parseHygonPubKey(data []byte) (*hygonPubKey, error) {
	if len(data) < OffsetECCPubKeyUserID+256 {
		return nil, errors.New("public key data too short")
	}
	curveID := binary.LittleEndian.Uint32(data)
	if curveID != CurveIDSM2 {
		return nil, fmt.Errorf("unsupported curve ID: 0x%x", curveID)
	}
	xBytes := ReverseCopy(data[OffsetECCPubKeyQX : OffsetECCPubKeyQX+32])
	yBytes := ReverseCopy(data[OffsetECCPubKeyQY : OffsetECCPubKeyQY+32])
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	uidData := data[OffsetECCPubKeyUserID:]
	uidLen := int(binary.LittleEndian.Uint16(uidData))
	if uidLen > len(uidData)-2 {
		return nil, fmt.Errorf("invalid SM2 user id length: %d", uidLen)
	}
	userID := append([]byte(nil), uidData[2:2+uidLen]...)
	return &hygonPubKey{
		Key:    &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y},
		UserID: userID,
		Details: PubKeyDetails{
			CurveID:   curveID,
			UserID:    string(userID),
			UserIDHex: hex.EncodeToString(userID),
			QXHex:     hex.EncodeToString(xBytes),
			QYHex:     hex.EncodeToString(yBytes),
		},
	}, nil
}

func ParseRootCertDetails(cert []byte) (RootCertDetails, error) {
	if len(cert) < HrkCertSize {
		return RootCertDetails{}, fmt.Errorf("certificate is %d bytes, need at least %d", len(cert), HrkCertSize)
	}
	pub, err := parseHygonPubKey(cert[OffsetRootPubKey:])
	if err != nil {
		return RootCertDetails{}, err
	}
	return RootCertDetails{KeyUsage: binary.LittleEndian.Uint32(cert[OffsetRootKeyUsage:]), PubKey: pub.Details}, nil
}

func ParseCSVCertDetails(cert []byte) (CSVCertDetails, error) {
	if len(cert) < CSVCertSize {
		return CSVCertDetails{}, fmt.Errorf("certificate is %d bytes, need at least %d", len(cert), CSVCertSize)
	}
	pub, err := parseHygonPubKey(cert[OffsetCSVPubKey:])
	if err != nil {
		return CSVCertDetails{}, err
	}
	return CSVCertDetails{
		PubKeyUsage: binary.LittleEndian.Uint32(cert[OffsetCSVPubKeyUsage:]),
		Sig1Usage:   binary.LittleEndian.Uint32(cert[OffsetCSVSig1Usage:]),
		Sig2Usage:   binary.LittleEndian.Uint32(cert[OffsetCSVSig2Usage:]),
		PubKey:      pub.Details,
	}, nil
}

func verifyHygonSignature(pub *hygonPubKey, msg []byte, sig []byte) bool {
	r, s := ParseHygonSignature(sig)
	return sm2.Sm2Verify(pub.Key, msg, pub.UserID, r, s)
}

// ParseHygonSignature splits a Hygon signature blob into its r and s halves.
//
// The layout is fixed: r occupies bytes [OffsetHygonSigR, OffsetHygonSigR+32)
// and s occupies [OffsetHygonSigS, OffsetHygonSigS+32), with padding between
// them, so sig must be at least OffsetHygonSigS+32 bytes. A shorter buffer
// yields (0, 0) rather than a slice-bounds panic. Zero is the fail-closed
// choice: sm2.Sm2Verify rejects r and s outside [1, N-1], so any verification
// that consumes them fails rather than accepting.
func ParseHygonSignature(sig []byte) (*big.Int, *big.Int) {
	if len(sig) < OffsetHygonSigS+32 {
		return new(big.Int), new(big.Int)
	}
	r := new(big.Int).SetBytes(ReverseCopy(sig[OffsetHygonSigR : OffsetHygonSigR+32]))
	s := new(big.Int).SetBytes(ReverseCopy(sig[OffsetHygonSigS : OffsetHygonSigS+32]))
	return r, s
}

func ChipIDASCII(chipID []byte) (string, error) {
	trimmed := strings.TrimSpace(strings.TrimRight(string(chipID), "\x00"))
	if trimmed == "" {
		return "", errors.New("ChipID is empty")
	}
	for _, b := range []byte(trimmed) {
		if b < 0x20 || b > 0x7e {
			return "", fmt.Errorf("ChipID contains a non-printable character: 0x%02x", b)
		}
	}
	return trimmed, nil
}

func readFixedFile(path string, size int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < size {
		return nil, fmt.Errorf("file is %d bytes, need at least %d", len(data), size)
	}
	return data[:size], nil
}

func ReverseCopy(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[len(in)-1-i]
	}
	return out
}
