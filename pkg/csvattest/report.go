package csvattest

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"fmt"

	gmsmsm3 "github.com/tjfoc/gmsm/sm3"
)

func hmacSM3(key, data []byte) [32]byte {
	h := hmac.New(gmsmsm3.New, key)
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func UnmaskWords(data []byte, anonce uint32) []byte {
	out := make([]byte, len(data))
	var i int
	for ; i+4 <= len(data); i += 4 {
		word := binary.LittleEndian.Uint32(data[i:i+4]) ^ anonce
		binary.LittleEndian.PutUint32(out[i:i+4], word)
	}
	copy(out[i:], data[i:])
	return out
}

func VerifySessionMAC(report, nonce []byte) error {
	if err := validateReportBytes(report); err != nil {
		return err
	}
	if err := validateNonce(nonce); err != nil {
		return err
	}

	macInput := report[OffsetPEKCert:OffsetMAC]
	got := hmacSM3(nonce, macInput)
	want := report[OffsetMAC : OffsetMAC+HashSize]
	if !hmac.Equal(got[:], want) {
		return ErrSessionMAC
	}
	return nil
}

func VerifyMNonce(report, nonce []byte) error {
	if err := validateReportBytes(report); err != nil {
		return err
	}
	if err := validateNonce(nonce); err != nil {
		return err
	}

	anonce := binary.LittleEndian.Uint32(report[OffsetANonce : OffsetANonce+4])
	mnonce := UnmaskWords(report[OffsetMNonce:OffsetMNonce+NonceSize], anonce)
	if !bytes.Equal(mnonce, nonce) {
		return ErrMNonceMismatch
	}
	return nil
}

func ExtractSealingKey(report []byte) ([]byte, error) {
	if err := validateReportBytes(report); err != nil {
		return nil, err
	}
	key := make([]byte, SealingKeySize)
	copy(key, report[OffsetReserved2:OffsetReserved2+SealingKeySize])
	return key, nil
}

func zeroReserved2(report []byte) error {
	if err := validateReportBytes(report); err != nil {
		return err
	}
	clear(report[OffsetReserved2 : OffsetReserved2+SealingKeySize])
	return nil
}

func validateReportBytes(report []byte) error {
	if len(report) < ReportSize {
		return fmt.Errorf("%w: report has %d bytes, need %d", ErrShortBuffer, len(report), ReportSize)
	}
	return nil
}
