package csvattest

import "fmt"

func (c *Client) GetAttestationReportVMMCall(reportBuf []byte) error {
	if err := validateReportBuffer(reportBuf); err != nil {
		return err
	}
	return fmt.Errorf("%w: vmmcall requires pagemap access and Go assembly or cgo", ErrUnsupported)
}

func (c *Client) GetSealingKeyVMMCall(keyBuf []byte) error {
	if len(keyBuf) < SealingKeySize {
		return fmt.Errorf("%w: sealing key buffer has %d bytes, need %d", ErrShortBuffer, len(keyBuf), SealingKeySize)
	}
	return fmt.Errorf("%w: vmmcall requires pagemap access and Go assembly or cgo", ErrUnsupported)
}
