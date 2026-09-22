package teetls

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/CipherSlinger/teetls/pkg/csvattest"
)

const (
	// DefaultMockMeasurementHex is the default dummy measurement hex used for mock attestation.
	DefaultMockMeasurementHex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
)

// EvidenceProvider retrieves CSV attestation evidence binding a public key digest.
type EvidenceProvider interface {
	GetEvidence(pubKeyDigest [32]byte) (*CSVEvidenceExtension, error)
	GetMeasurementHex() string
}

// ContextEvidenceProvider retrieves CSV attestation evidence with cancellation support.
type ContextEvidenceProvider interface {
	GetEvidenceContext(ctx context.Context, pubKeyDigest [32]byte) (*CSVEvidenceExtension, error)
}

// TrustedHRKProvider exposes locally trusted HRK material for test or offline configurations.
type TrustedHRKProvider interface {
	TrustedHRKCert() []byte
}

// MockEvidenceProvider implements EvidenceProvider for unit testing with cryptographically valid SM2-signed reports.
type MockEvidenceProvider struct {
	MeasurementHex string
	HRKCert        []byte
	HSKCekCert     []byte

	mu        sync.Mutex
	authority *csvattest.MockAttestationAuthority
	initErr   error
}

// NewMockEvidenceProvider creates a new MockEvidenceProvider with default test data.
func NewMockEvidenceProvider() *MockEvidenceProvider {
	authority, err := csvattest.NewMockAttestationAuthority()
	p := &MockEvidenceProvider{
		MeasurementHex: DefaultMockMeasurementHex,
		authority:      authority,
		initErr:        err,
	}
	if authority != nil {
		p.HRKCert = authority.HRKCert()
		p.HSKCekCert = authority.HSKCekCert()
	}
	return p
}

// GetEvidence produces a cryptographically signed mock report with UserData, Measurement, and certificate chain.
func (m *MockEvidenceProvider) GetEvidence(pubKeyDigest [32]byte) (*CSVEvidenceExtension, error) {
	authority, err := m.attestationAuthority()
	if err != nil {
		return nil, err
	}

	report, hrkCert, hskCekCert, err := authority.Generate(pubKeyDigest[:], m.MeasurementHex)
	if err != nil {
		return nil, fmt.Errorf("generate mock attestation data: %w", err)
	}

	return &CSVEvidenceExtension{
		Version:    1,
		Report:     report,
		HRKCert:    hrkCert,
		HSKCekCert: hskCekCert,
	}, nil
}

// attestationAuthority returns the shared mock authority, creating it on first
// use when construction failed so that concurrent callers cannot race on it.
func (m *MockEvidenceProvider) attestationAuthority() (*csvattest.MockAttestationAuthority, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initErr != nil {
		return nil, fmt.Errorf("initialize mock attestation authority: %w", m.initErr)
	}
	if m.authority == nil {
		authority, err := csvattest.NewMockAttestationAuthority()
		if err != nil {
			return nil, fmt.Errorf("initialize mock attestation authority: %w", err)
		}
		m.authority = authority
		m.HRKCert = authority.HRKCert()
		m.HSKCekCert = authority.HSKCekCert()
	}
	return m.authority, nil
}

// GetEvidenceContext produces mock evidence and observes pre-call cancellation.
func (m *MockEvidenceProvider) GetEvidenceContext(ctx context.Context, pubKeyDigest [32]byte) (*CSVEvidenceExtension, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return m.GetEvidence(pubKeyDigest)
}

// TrustedHRKCert returns the mock HRK certificate that callers must trust explicitly.
func (m *MockEvidenceProvider) TrustedHRKCert() []byte {
	return append([]byte(nil), m.HRKCert...)
}

// GetMeasurementHex returns the mock measurement hex string.
func (m *MockEvidenceProvider) GetMeasurementHex() string {
	return m.MeasurementHex
}

// HygonHardwareProvider implements EvidenceProvider on real Hygon CSV hardware.
type HygonHardwareProvider struct {
	DevicePath     string
	HRKCertPath    string
	HSKCekCertPath string
}

// NewHygonHardwareProvider creates an EvidenceProvider backed by /dev/csv-guest.
func NewHygonHardwareProvider(devicePath, hrkPath, hskCekPath string) *HygonHardwareProvider {
	if devicePath == "" {
		devicePath = "/dev/csv-guest"
	}
	return &HygonHardwareProvider{
		DevicePath:     devicePath,
		HRKCertPath:    hrkPath,
		HSKCekCertPath: hskCekPath,
	}
}

// GetEvidenceContext communicates with the hardware driver to retrieve attestation report and cert chain.
func (h *HygonHardwareProvider) GetEvidenceContext(ctx context.Context, pubKeyDigest [32]byte) (*CSVEvidenceExtension, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return h.GetEvidence(pubKeyDigest)
}

// TrustedHRKCert returns configured local HRK material when available.
func (h *HygonHardwareProvider) TrustedHRKCert() []byte {
	if h.HRKCertPath == "" {
		return nil
	}
	data, err := readCertFile(h.HRKCertPath, csvattest.HrkCertSize)
	if err != nil {
		return nil
	}
	return data
}

// readCertFile reads a fixed-layout Hygon certificate file and normalises it to
// size bytes. Trailing bytes such as a newline are dropped, so that the anchor
// comparison and the evidence encoding both see the exact certificate.
func readCertFile(path string, size int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < size {
		return nil, fmt.Errorf("certificate file %s is %d bytes, need at least %d", path, len(data), size)
	}
	return append([]byte(nil), data[:size]...), nil
}

// GetEvidence communicates with the hardware driver to retrieve attestation report and cert chain.
func (h *HygonHardwareProvider) GetEvidence(pubKeyDigest [32]byte) (*CSVEvidenceExtension, error) {
	// UserData for CSV hardware is 64 bytes. We place pubKeyDigest in first 32 bytes.
	userData := make([]byte, csvattest.UserDataSize)
	copy(userData[:32], pubKeyDigest[:])

	client := csvattest.NewClient(
		csvattest.WithDevicePath(h.DevicePath),
		csvattest.WithUserData(userData),
	)

	reportBuf := make([]byte, csvattest.ReportSize)
	nonce := make([]byte, csvattest.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate hardware attestation nonce: %w", err)
	}
	if err := client.GetAttestationReportIOCTL(reportBuf, nonce); err != nil {
		return nil, fmt.Errorf("fetch attestation report from hardware: %w", err)
	}

	var hrkCert []byte
	if h.HRKCertPath != "" {
		data, err := readCertFile(h.HRKCertPath, csvattest.HrkCertSize)
		if err != nil {
			return nil, fmt.Errorf("read hrk cert: %w", err)
		}
		hrkCert = data
	}

	var hskCekCert []byte
	if h.HSKCekCertPath != "" {
		data, err := readCertFile(h.HSKCekCertPath, csvattest.HskCekSize)
		if err != nil {
			return nil, fmt.Errorf("read hsk_cek cert: %w", err)
		}
		hskCekCert = data
	}

	return &CSVEvidenceExtension{
		Version:    1,
		Report:     reportBuf,
		HRKCert:    hrkCert,
		HSKCekCert: hskCekCert,
	}, nil
}

// GetMeasurementHex extracts the measurement hash from hardware report or returns empty if not available.
func (h *HygonHardwareProvider) GetMeasurementHex() string {
	// Dummy digest for hardware query
	var dummy [32]byte
	ev, err := h.GetEvidence(dummy)
	if err != nil || len(ev.Report) < csvattest.ReportSize {
		return ""
	}
	res, err := csvattest.ParseReport(ev.Report)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(res.Digest)
}

// Ensure interface compliance at compile time.
var (
	_ EvidenceProvider = (*MockEvidenceProvider)(nil)
	_ EvidenceProvider = (*HygonHardwareProvider)(nil)
)
