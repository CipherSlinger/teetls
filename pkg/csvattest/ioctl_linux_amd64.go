//go:build linux && amd64

package csvattest

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"

	gmsmsm3 "github.com/tjfoc/gmsm/sm3"
)

type defaultPlatformOps struct{}

type csvGuestMem struct {
	VA   uintptr
	Size int32
	_    [4]byte
}

func (defaultPlatformOps) mmap(length int) ([]byte, error) {
	return syscall.Mmap(-1, 0, length, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
}

func (defaultPlatformOps) munmap(page []byte) error {
	return syscall.Munmap(page)
}

func (defaultPlatformOps) openDevice(path string) (ioctlDevice, error) {
	return os.OpenFile(path, os.O_RDWR, 0)
}

func (defaultPlatformOps) ioctl(fd uintptr, req uintptr, mem *csvGuestMem) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(mem)))
	if errno != 0 {
		return errno
	}
	return nil
}

func (c *Client) GetAttestationReportIOCTL(reportBuf, nonce []byte) error {
	if c == nil {
		c = NewClient()
	}
	if err := validateReportBuffer(reportBuf); err != nil {
		return err
	}

	report, err := c.fetchReportIOCTL(nonce)
	if err != nil {
		return err
	}
	if err := zeroReserved2(report); err != nil {
		return err
	}
	copy(reportBuf, report)
	return nil
}

func (c *Client) GetSealingKeyIOCTL(keyBuf []byte) error {
	if c == nil {
		c = NewClient()
	}
	if len(keyBuf) < SealingKeySize {
		return fmt.Errorf("%w: sealing key buffer has %d bytes, need %d", ErrShortBuffer, len(keyBuf), SealingKeySize)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(c.Rand, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	report, err := c.fetchReportIOCTL(nonce)
	if err != nil {
		return err
	}
	key, err := ExtractSealingKey(report)
	if err != nil {
		return err
	}
	copy(keyBuf, key)
	return nil
}

func (c *Client) fetchReportIOCTL(nonce []byte) ([]byte, error) {
	if err := validateNonce(nonce); err != nil {
		return nil, err
	}
	userData, err := c.userData()
	if err != nil {
		return nil, err
	}

	page, err := c.ops.mmap(PageSize)
	if err != nil {
		return nil, fmt.Errorf("allocate attestation page: %w", err)
	}
	defer c.ops.munmap(page)

	copy(page[:UserDataSize], userData)
	copy(page[UserDataSize:UserDataSize+NonceSize], nonce)
	hashInputEnd := UserDataSize + NonceSize
	hash := gmsmsm3.Sm3Sum(page[:hashInputEnd])
	copy(page[hashInputEnd:hashInputEnd+HashSize], hash)

	dev, err := c.ops.openDevice(c.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", c.DevicePath, err)
	}
	defer dev.Close()

	mem := csvGuestMem{VA: uintptr(unsafe.Pointer(&page[0])), Size: PageSize}
	if err := c.ops.ioctl(dev.Fd(), getAttestationReportIOCT, &mem); err != nil {
		return nil, fmt.Errorf("ioctl get attestation report: %w", err)
	}

	report := make([]byte, ReportSize)
	copy(report, page[:ReportSize])
	if err := VerifySessionMAC(report, nonce); err != nil {
		return nil, err
	}
	if err := VerifyMNonce(report, nonce); err != nil {
		return nil, err
	}
	return report, nil
}
