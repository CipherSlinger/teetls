package teetls

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/tjfoc/gmsm/sm4"
)

// RecordType represents the TLS 1.3 ContentType or Inner Plaintext ContentType.
type RecordType uint8

const (
	// RecordTypeChangeCipherSpec is retained for compatibility in TLS 1.3.
	RecordTypeChangeCipherSpec RecordType = 20
	// RecordTypeAlert represents TLS alert messages.
	RecordTypeAlert RecordType = 21
	// RecordTypeHandshake represents TLS handshake messages.
	RecordTypeHandshake RecordType = 22
	// RecordTypeApplicationData represents TLS application data.
	RecordTypeApplicationData RecordType = 23
)

const (
	// RecordHeaderLen is the size in bytes of the TLS record header.
	RecordHeaderLen = 5
	// LegacyRecordVersion is TLS 1.2 legacy version 0x0303 mandated by TLS 1.3.
	LegacyRecordVersion uint16 = 0x0303
	// MaxPlaintextLength is the maximum plaintext fragment size (2^14 = 16384 bytes).
	MaxPlaintextLength = 16384
	// MaxCiphertextLength is the maximum encrypted record length (2^14 + 256 bytes).
	MaxCiphertextLength = 16384 + 256
	// SM4KeySize is the required key length for SM4 (16 bytes / 128 bits).
	SM4KeySize = 16
	// GCMNonceSize is the required nonce size for GCM (12 bytes / 96 bits).
	GCMNonceSize = 12
	// GCMTagSize is the authentication tag size produced by GCM (16 bytes).
	GCMTagSize = 16
)

var (
	// ErrInvalidKeySize is returned when key length is not SM4KeySize.
	ErrInvalidKeySize = errors.New("teetls: invalid SM4 key length, must be 16 bytes")
	// ErrInvalidIVSize is returned when base IV length is not GCMNonceSize.
	ErrInvalidIVSize = errors.New("teetls: invalid IV length, must be 12 bytes")
	// ErrPlaintextTooLarge is returned when plaintext exceeds MaxPlaintextLength.
	ErrPlaintextTooLarge = errors.New("teetls: plaintext exceeds maximum allowed length")
	// ErrCiphertextTooLarge is returned when ciphertext payload exceeds MaxCiphertextLength.
	ErrCiphertextTooLarge = errors.New("teetls: ciphertext exceeds maximum allowed length")
	// ErrRecordTooShort is returned when record buffer is smaller than the minimum possible record.
	ErrRecordTooShort = errors.New("teetls: record buffer is too short")
	// ErrInvalidRecordHeader is returned when outer header fields (opaque_type, legacy_version) are invalid.
	ErrInvalidRecordHeader = errors.New("teetls: invalid TLS 1.3 outer record header")
	// ErrRecordLengthMismatch is returned when outer record header length does not match payload size.
	ErrRecordLengthMismatch = errors.New("teetls: record length in header does not match data length")
	// ErrZeroPaddingOnly is returned when non-zero bytes are found after content type or no content type found.
	ErrNoContentType = errors.New("teetls: inner plaintext does not contain valid content type")
	// ErrSequenceOverflow is returned when the 64-bit sequence number overflows.
	ErrSequenceOverflow = errors.New("teetls: sequence number overflow")
	// ErrInvalidInnerContentType is returned when decrypted TLSInnerPlaintext has an unsupported type.
	ErrInvalidInnerContentType = errors.New("teetls: invalid inner plaintext content type")
)

// RecordCipher handles RFC 8998 TLS 1.3 record layer encryption and decryption using SM4-GCM.
type RecordCipher struct {
	mu     sync.Mutex
	aead   cipher.AEAD
	baseIV [GCMNonceSize]byte
	seq    uint64
}

// NewRecordCipher creates a new RecordCipher with the given SM4 key and base IV.
func NewRecordCipher(key, iv []byte) (*RecordCipher, error) {
	if len(key) != SM4KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(iv) != GCMNonceSize {
		return nil, ErrInvalidIVSize
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("teetls: create sm4 cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("teetls: create gcm aead: %w", err)
	}

	rc := &RecordCipher{
		aead: gcm,
	}
	copy(rc.baseIV[:], iv)
	return rc, nil
}

// Sequence returns the current 64-bit sequence number.
func (rc *RecordCipher) Sequence() uint64 {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.seq
}

// Reset is deprecated and intentionally does nothing.
// Resetting sequence numbers with the same SM4-GCM key/IV would reuse nonces.
func (rc *RecordCipher) Reset() {
}

// Seal encrypts a plaintext payload with the specified ContentType, applying zero padding bytes.
// It constructs the TLS 1.3 outer record header (5 bytes), computes nonce from seq XOR baseIV,
// seals with SM4-GCM using the 5-byte header as AAD, and increments the sequence number.
func (rc *RecordCipher) Seal(contentType RecordType, plaintext []byte) ([]byte, error) {
	return rc.SealWithPadding(contentType, plaintext, 0)
}

// SealWithPadding encrypts plaintext with optional zero-byte padding.
func (rc *RecordCipher) SealWithPadding(contentType RecordType, plaintext []byte, paddingLen int) ([]byte, error) {
	if len(plaintext) > MaxPlaintextLength {
		return nil, ErrPlaintextTooLarge
	}
	if paddingLen < 0 {
		return nil, errors.New("teetls: padding length cannot be negative")
	}

	innerLen := len(plaintext) + 1 + paddingLen
	ciphertextLen := innerLen + GCMTagSize
	if ciphertextLen > MaxCiphertextLength {
		return nil, ErrCiphertextTooLarge
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.seq == ^uint64(0) {
		return nil, ErrSequenceOverflow
	}

	// 1. Prepare inner plaintext: plaintext || contentType || zeros(paddingLen)
	innerPlaintext := make([]byte, innerLen)
	copy(innerPlaintext, plaintext)
	innerPlaintext[len(plaintext)] = byte(contentType)
	// Trailing bytes default to 0x00

	// 2. Prepare 5-byte outer record header:
	// opaque_type (0x17) || legacy_record_version (0x0303) || length (ciphertextLen)
	var header [RecordHeaderLen]byte
	header[0] = byte(RecordTypeApplicationData) // 23 (0x17)
	binary.BigEndian.PutUint16(header[1:3], LegacyRecordVersion)
	binary.BigEndian.PutUint16(header[3:5], uint16(ciphertextLen))

	// 3. Compute 12-byte nonce: baseIV ^ (0x00000000 || seq_64bit)
	nonce := rc.deriveNonce(rc.seq)

	// 4. Seal inner plaintext using outer header as Additional Authenticated Data (AAD)
	// Preallocate full record buffer: header (5 bytes) + ciphertext + tag
	record := make([]byte, RecordHeaderLen, RecordHeaderLen+ciphertextLen)
	copy(record, header[:])

	record = rc.aead.Seal(record, nonce[:], innerPlaintext, header[:])

	// 5. Increment sequence number
	rc.seq++

	return record, nil
}

// Unseal decrypts and authenticates a TLS 1.3 record.
// It verifies the outer header, derives nonce from current seq XOR baseIV,
// decrypts using header as AAD, strips optional padding and extracts real ContentType.
// On success, it increments the sequence number.
func (rc *RecordCipher) Unseal(record []byte) (RecordType, []byte, error) {
	// Minimum record size: 5-byte header + 1-byte content type + 16-byte tag = 22 bytes
	if len(record) < RecordHeaderLen+1+GCMTagSize {
		return 0, nil, ErrRecordTooShort
	}

	// 1. Validate outer record header
	if record[0] != byte(RecordTypeApplicationData) {
		return 0, nil, ErrInvalidRecordHeader
	}
	legacyVer := binary.BigEndian.Uint16(record[1:3])
	if legacyVer != LegacyRecordVersion {
		return 0, nil, ErrInvalidRecordHeader
	}

	declaredLen := int(binary.BigEndian.Uint16(record[3:5]))
	if declaredLen != len(record)-RecordHeaderLen {
		return 0, nil, ErrRecordLengthMismatch
	}
	if declaredLen > MaxCiphertextLength {
		return 0, nil, ErrCiphertextTooLarge
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.seq == ^uint64(0) {
		return 0, nil, ErrSequenceOverflow
	}

	header := record[:RecordHeaderLen]
	ciphertext := record[RecordHeaderLen:]

	// 2. Compute nonce: baseIV ^ (0x00000000 || seq_64bit)
	nonce := rc.deriveNonce(rc.seq)

	// 3. Authenticate and decrypt with AAD
	decrypted, err := rc.aead.Open(nil, nonce[:], ciphertext, header)
	if err != nil {
		return 0, nil, fmt.Errorf("teetls: open record: %w", err)
	}

	// 4. Extract real content type and strip padding
	// RFC 8446 Section 5.4 / RFC 8998:
	// Inner plaintext has format: content || real_content_type || zeros
	// Scan from end to find first non-zero byte, which is real_content_type.
	idx := len(decrypted) - 1
	for idx >= 0 && decrypted[idx] == 0 {
		idx--
	}
	if idx < 0 {
		return 0, nil, ErrNoContentType
	}

	realContentType := RecordType(decrypted[idx])
	if realContentType != RecordTypeAlert && realContentType != RecordTypeHandshake && realContentType != RecordTypeApplicationData {
		return 0, nil, ErrInvalidInnerContentType
	}
	plaintext := decrypted[:idx]

	if len(plaintext) > MaxPlaintextLength {
		return 0, nil, ErrPlaintextTooLarge
	}

	// 5. Increment sequence number
	rc.seq++

	return realContentType, plaintext, nil
}

// deriveNonce calculates: baseIV ^ (0x00000000 || seq_64bit)
func (rc *RecordCipher) deriveNonce(seq uint64) [GCMNonceSize]byte {
	var nonce [GCMNonceSize]byte
	copy(nonce[:], rc.baseIV[:])

	// The sequence number is converted to an 8-byte big-endian integer,
	// zero-padded on the left to 12 bytes, and XORed with baseIV.
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)

	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}
	return nonce
}
