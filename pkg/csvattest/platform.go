package csvattest

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
