package teetls

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

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

// MockEvidenceProvider implements EvidenceProvider for unit testing with cryptographically valid SM2-signed reports.
type MockEvidenceProvider struct {
	MeasurementHex string
	HRKCert        []byte
	HSKCekCert     []byte
}

// NewMockEvidenceProvider creates a new MockEvidenceProvider with default test data.
func NewMockEvidenceProvider() *MockEvidenceProvider {
	return &MockEvidenceProvider{
		MeasurementHex: DefaultMockMeasurementHex,
	}
}

// GetEvidence produces a cryptographically signed mock report with UserData, Measurement, and certificate chain.
func (m *MockEvidenceProvider) GetEvidence(pubKeyDigest [32]byte) (*CSVEvidenceExtension, error) {
	report, hrkCert, hskCekCert, err := csvattest.GenerateMockAttestationData(pubKeyDigest[:], m.MeasurementHex)
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
		data, err := os.ReadFile(h.HRKCertPath)
		if err != nil {
			return nil, fmt.Errorf("read hrk cert: %w", err)
		}
		hrkCert = data
	}

	var hskCekCert []byte
	if h.HSKCekCertPath != "" {
		data, err := os.ReadFile(h.HSKCekCertPath)
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
