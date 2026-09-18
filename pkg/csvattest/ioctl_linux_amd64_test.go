//go:build linux && amd64

package csvattest

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	gmsmsm3 "github.com/tjfoc/gmsm/sm3"
)

type fakeOps struct {
	page    []byte
	ioctlFn func(page []byte, mem *csvGuestMem) error
}

func (f *fakeOps) mmap(length int) ([]byte, error) {
	f.page = make([]byte, length)
	return f.page, nil
}

func (f *fakeOps) munmap(page []byte) error { return nil }

func (f *fakeOps) openDevice(path string) (ioctlDevice, error) { return fakeDevice(42), nil }

func (f *fakeOps) ioctl(fd uintptr, req uintptr, mem *csvGuestMem) error {
	if fd != 42 {
		return fmt.Errorf("fd = %d, want 42", fd)
	}
	if req != getAttestationReportIOCT {
		return fmt.Errorf("req = %#x, want %#x", req, getAttestationReportIOCT)
	}
	return f.ioctlFn(f.page, mem)
}

type fakeDevice uintptr

func (f fakeDevice) Fd() uintptr  { return uintptr(f) }
func (f fakeDevice) Close() error { return nil }

func TestGetAttestationReportIOCTLWithFakeDevice(t *testing.T) {
	userData := bytes.Repeat([]byte{0xa5}, UserDataSize)
	nonce := []byte("1234567890abcdef")
	reserved2 := bytes.Repeat([]byte{0x6b}, SealingKeySize)

	ops := &fakeOps{ioctlFn: func(page []byte, mem *csvGuestMem) error {
		if mem.Size != PageSize {
			return fmt.Errorf("mem.Size = %d, want %d", mem.Size, PageSize)
		}
		if mem.VA == 0 {
			return fmt.Errorf("mem.VA is zero")
		}
		mapped := page
		if !bytes.Equal(mapped[:UserDataSize], userData) {
			return fmt.Errorf("userdata = %x, want %x", mapped[:UserDataSize], userData)
		}
		if !bytes.Equal(mapped[UserDataSize:UserDataSize+NonceSize], nonce) {
			return fmt.Errorf("nonce = %x, want %x", mapped[UserDataSize:UserDataSize+NonceSize], nonce)
		}
		hashInput := append(append([]byte(nil), userData...), nonce...)
		wantHash := gmsmsm3.Sm3Sum(hashInput)
		if !bytes.Equal(mapped[UserDataSize+NonceSize:UserDataSize+NonceSize+HashSize], wantHash) {
			return fmt.Errorf("userdata hash mismatch")
		}
		copy(mapped, syntheticReport(nonce, reserved2))
		return nil
	}}

	report := make([]byte, ReportSize)
	client := NewClient(WithUserData(userData))
	client.ops = ops
	if err := client.GetAttestationReportIOCTL(report, nonce); err != nil {
		t.Fatalf("GetAttestationReportIOCTL() error = %v", err)
	}
	if !bytes.Equal(report[OffsetReserved2:OffsetReserved2+SealingKeySize], make([]byte, SealingKeySize)) {
		t.Fatalf("reserved2 was not zeroed in attestation report")
	}
	if err := VerifyMNonce(report, nonce); err != nil {
		t.Fatalf("returned report mnonce verification failed: %v", err)
	}
}

func TestGetSealingKeyIOCTLWithFakeDevice(t *testing.T) {
	userData := bytes.Repeat([]byte{0x2a}, UserDataSize)
	nonce := []byte("abcdef1234567890")
	reserved2 := bytes.Repeat([]byte{0x7c}, SealingKeySize)

	ops := &fakeOps{ioctlFn: func(page []byte, mem *csvGuestMem) error {
		if mem.Size != PageSize || mem.VA == 0 {
			return fmt.Errorf("invalid csvGuestMem: %+v", mem)
		}
		mapped := page
		if !bytes.Equal(mapped[UserDataSize:UserDataSize+NonceSize], nonce) {
			return fmt.Errorf("nonce = %x, want %x", mapped[UserDataSize:UserDataSize+NonceSize], nonce)
		}
		copy(mapped, syntheticReport(nonce, reserved2))
		return nil
	}}

	client := NewClient(WithUserData(userData), WithRand(bytes.NewReader(nonce)))
	client.ops = ops
	key := make([]byte, SealingKeySize)
	if err := client.GetSealingKeyIOCTL(key); err != nil {
		t.Fatalf("GetSealingKeyIOCTL() error = %v", err)
	}
	if !bytes.Equal(key, reserved2) {
		t.Fatalf("GetSealingKeyIOCTL() = %x, want %x", key, reserved2)
	}
}

func TestGetAttestationReportIOCTLValidation(t *testing.T) {
	client := NewClient()
	client.ops = &fakeOps{}
	if err := client.GetAttestationReportIOCTL(make([]byte, ReportSize-1), make([]byte, NonceSize)); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("short report error = %v, want ErrShortBuffer", err)
	}
	if err := client.GetAttestationReportIOCTL(make([]byte, ReportSize), make([]byte, NonceSize-1)); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("short nonce error = %v, want ErrInvalidNonce", err)
	}
}
