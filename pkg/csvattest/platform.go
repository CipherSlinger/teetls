package csvattest

import "unsafe"

// csvGuestMem mirrors the memory descriptor struct expected by the csv-guest
// driver ioctl interface. It is declared here, without a build constraint, so
// that the platformOps interface and its fallback implementation remain
// compilable on every supported platform. The layout assumes a 64-bit target.
type csvGuestMem struct {
	VA   uintptr
	Size int32
	_    [4]byte
}

// The driver expects a csvGuestMemSize-byte descriptor. On a 32-bit target
// uintptr is 4 bytes wide, which would silently produce a malformed descriptor,
// so fail the build instead. Both bounds must hold for the assertion to compile.
var (
	_ [unsafe.Sizeof(csvGuestMem{}) - csvGuestMemSize]byte
	_ [csvGuestMemSize - unsafe.Sizeof(csvGuestMem{})]byte
)

type platformOps interface {
	mmap(length int) ([]byte, error)
	munmap(page []byte) error
	openDevice(path string) (ioctlDevice, error)
	ioctl(fd uintptr, req uintptr, mem *csvGuestMem) error
}

type ioctlDevice interface {
	Fd() uintptr
	Close() error
}
