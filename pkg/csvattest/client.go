package csvattest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

type Client struct {
	DevicePath string
	UserData   []byte
	Rand       io.Reader

	ops platformOps
}

type Option func(*Client)

func NewClient(opts ...Option) *Client {
	c := &Client{
		DevicePath: defaultCSVGuestDevice,
		Rand:       rand.Reader,
		ops:        defaultPlatformOps{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.DevicePath == "" {
		c.DevicePath = defaultCSVGuestDevice
	}
	if c.ops == nil {
		c.ops = defaultPlatformOps{}
	}
	return c
}

func WithDevicePath(path string) Option {
	return func(c *Client) {
		c.DevicePath = strings.TrimSpace(path)
	}
}

func WithUserData(userData []byte) Option {
	return func(c *Client) {
		c.UserData = append([]byte(nil), userData...)
	}
}

func WithRand(r io.Reader) Option {
	return func(c *Client) {
		c.Rand = r
	}
}

func GetAttestationReportIOCTL(reportBuf, nonce []byte) error {
	return NewClient().GetAttestationReportIOCTL(reportBuf, nonce)
}

func GetAttestationReportVMMCall(reportBuf []byte) error {
	return NewClient().GetAttestationReportVMMCall(reportBuf)
}

func VerifyAttestationReport(reportBuf []byte, verifyChain bool) error {
	return NewClient().VerifyAttestationReport(reportBuf, verifyChain)
}

func GetSealingKeyIOCTL(keyBuf []byte) error {
	return NewClient().GetSealingKeyIOCTL(keyBuf)
}

func GetSealingKeyVMMCall(keyBuf []byte) error {
	return NewClient().GetSealingKeyVMMCall(keyBuf)
}

func (c *Client) userData() ([]byte, error) {
	if len(c.UserData) > 0 {
		if len(c.UserData) != UserDataSize {
			return nil, fmt.Errorf("%w: got %d bytes, need %d", ErrInvalidUserData, len(c.UserData), UserDataSize)
		}
		return append([]byte(nil), c.UserData...), nil
	}

	if value := strings.TrimSpace(os.Getenv("ATTESTATION_USERDATA")); value != "" {
		if len(value) != UserDataSize*2 {
			return nil, fmt.Errorf("%w: ATTESTATION_USERDATA has %d hex chars, need %d", ErrInvalidUserData, len(value), UserDataSize*2)
		}
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("%w: decode ATTESTATION_USERDATA: %v", ErrInvalidUserData, err)
		}
		return decoded, nil
	}

	data := make([]byte, UserDataSize)
	copy(data, defaultUserDataText)
	return data, nil
}

func validateReportBuffer(reportBuf []byte) error {
	if len(reportBuf) < ReportSize {
		return fmt.Errorf("%w: report buffer has %d bytes, need %d", ErrShortBuffer, len(reportBuf), ReportSize)
	}
	return nil
}

func validateNonce(nonce []byte) error {
	if len(nonce) != NonceSize {
		return fmt.Errorf("%w: nonce has %d bytes, need %d", ErrInvalidNonce, len(nonce), NonceSize)
	}
	return nil
}
