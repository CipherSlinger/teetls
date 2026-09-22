//go:build !linux

package csvattest

import "fmt"

// defaultPlatformOps is the stub used on non-Linux hosts. It satisfies
// platformOps so that the package builds everywhere, but every operation
// fails closed with ErrUnsupported.
type defaultPlatformOps struct{}

func (defaultPlatformOps) mmap(length int) ([]byte, error) {
	return nil, fmt.Errorf("%w: attestation requires linux", ErrUnsupported)
}

func (defaultPlatformOps) munmap(page []byte) error {
	return fmt.Errorf("%w: attestation requires linux", ErrUnsupported)
}

func (defaultPlatformOps) openDevice(path string) (ioctlDevice, error) {
	return nil, fmt.Errorf("%w: attestation requires linux", ErrUnsupported)
}

func (defaultPlatformOps) ioctl(fd uintptr, req uintptr, mem *csvGuestMem) error {
	return fmt.Errorf("%w: attestation requires linux", ErrUnsupported)
}

func (c *Client) GetAttestationReportIOCTL(reportBuf, nonce []byte) error {
	if err := validateReportBuffer(reportBuf); err != nil {
		return err
	}
	if err := validateNonce(nonce); err != nil {
		return err
	}
	return fmt.Errorf("%w: ioctl attestation requires linux", ErrUnsupported)
}

func (c *Client) GetSealingKeyIOCTL(keyBuf []byte) error {
	if len(keyBuf) < SealingKeySize {
		return fmt.Errorf("%w: sealing key buffer has %d bytes, need %d", ErrShortBuffer, len(keyBuf), SealingKeySize)
	}
	return fmt.Errorf("%w: ioctl attestation requires linux", ErrUnsupported)
}
