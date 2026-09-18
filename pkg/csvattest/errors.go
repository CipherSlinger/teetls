package csvattest

import "errors"

var (
	ErrUnsupported     = errors.New("csvattest: unsupported operation")
	ErrShortBuffer     = errors.New("csvattest: buffer too short")
	ErrInvalidNonce    = errors.New("csvattest: invalid nonce length")
	ErrInvalidUserData = errors.New("csvattest: invalid user data")
	ErrSessionMAC      = errors.New("csvattest: session MAC verification failed")
	ErrMNonceMismatch  = errors.New("csvattest: report mnonce does not match request nonce")
)
