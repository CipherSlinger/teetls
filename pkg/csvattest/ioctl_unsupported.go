//go:build !linux || !amd64

package csvattest

import "fmt"

type defaultPlatformOps struct{}

func (c *Client) GetAttestationReportIOCTL(reportBuf, nonce []byte) error {
	if err := validateReportBuffer(reportBuf); err != nil {
		return err
	}
	if err := validateNonce(nonce); err != nil {
		return err
	}
	return fmt.Errorf("%w: ioctl attestation requires linux/amd64", ErrUnsupported)
}

func (c *Client) GetSealingKeyIOCTL(keyBuf []byte) error {
	if len(keyBuf) < SealingKeySize {
		return fmt.Errorf("%w: sealing key buffer has %d bytes, need %d", ErrShortBuffer, len(keyBuf), SealingKeySize)
	}
	return fmt.Errorf("%w: ioctl attestation requires linux/amd64", ErrUnsupported)
}
