package teetls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestRecordLayer_SealAndUnseal(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes for SM4
	iv := []byte("123456789012")     // 12 bytes for GCM IV

	sender, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher sender: %v", err)
	}
	receiver, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher receiver: %v", err)
	}

	payload := []byte("Hello RFC 8998 ShangMi TLS 1.3 Record Layer")
	record, err := sender.Seal(RecordTypeApplicationData, payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	contentType, plaintext, err := receiver.Unseal(record)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if contentType != RecordTypeApplicationData {
		t.Errorf("expected content type %d, got %d", RecordTypeApplicationData, contentType)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Errorf("plaintext mismatch: got %s, want %s", plaintext, payload)
	}

	// Verify sequence number increment prevents replay
	_, _, err = receiver.Unseal(record)
	if err == nil {
		t.Fatalf("expected unseal error on replayed record")
	}
}

func TestRecordLayer_SequenceNumberAntiReplay(t *testing.T) {
	key := make([]byte, SM4KeySize)
	iv := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("read key: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatalf("read iv: %v", err)
	}

	sender, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher sender: %v", err)
	}
	receiver, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher receiver: %v", err)
	}

	records := make([][]byte, 3)
	payloads := [][]byte{
		[]byte("record zero payload"),
		[]byte("record one payload"),
		[]byte("record two payload"),
	}

	for i := 0; i < 3; i++ {
		r, err := sender.Seal(RecordTypeApplicationData, payloads[i])
		if err != nil {
			t.Fatalf("seal record %d: %v", i, err)
		}
		records[i] = r
	}

	// First unseal of record 0 should succeed
	ct, pt, err := receiver.Unseal(records[0])
	if err != nil {
		t.Fatalf("unseal record 0: %v", err)
	}
	if ct != RecordTypeApplicationData || !bytes.Equal(pt, payloads[0]) {
		t.Fatalf("record 0 mismatch")
	}

	// Immediate replay of record 0 must fail because receiver sequence advanced to 1
	if _, _, err := receiver.Unseal(records[0]); err == nil {
		t.Fatalf("expected replay of record 0 to fail")
	}

	// Out-of-order unseal: trying record 2 while receiver expects record 1 must fail
	if _, _, err := receiver.Unseal(records[2]); err == nil {
		t.Fatalf("expected out-of-order record 2 to fail")
	}

	// Receiver now expects record 1
	ct, pt, err = receiver.Unseal(records[1])
	if err != nil {
		t.Fatalf("unseal record 1: %v", err)
	}
	if ct != RecordTypeApplicationData || !bytes.Equal(pt, payloads[1]) {
		t.Fatalf("record 1 mismatch")
	}

	// Receiver now expects record 2
	ct, pt, err = receiver.Unseal(records[2])
	if err != nil {
		t.Fatalf("unseal record 2: %v", err)
	}
	if ct != RecordTypeApplicationData || !bytes.Equal(pt, payloads[2]) {
		t.Fatalf("record 2 mismatch")
	}
}

func TestRecordLayer_Padding(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("123456789012")

	sender, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher sender: %v", err)
	}
	receiver, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher receiver: %v", err)
	}

	paddingSizes := []int{0, 1, 5, 16, 64, 255}
	payload := []byte("message with variable padding")

	for _, padLen := range paddingSizes {
		record, err := sender.SealWithPadding(RecordTypeApplicationData, payload, padLen)
		if err != nil {
			t.Fatalf("SealWithPadding (padLen=%d): %v", padLen, err)
		}

		expectedRecordLen := RecordHeaderLen + len(payload) + 1 + padLen + GCMTagSize
		if len(record) != expectedRecordLen {
			t.Errorf("padLen %d: expected record length %d, got %d", padLen, expectedRecordLen, len(record))
		}

		ct, pt, err := receiver.Unseal(record)
		if err != nil {
			t.Fatalf("Unseal (padLen=%d): %v", padLen, err)
		}
		if ct != RecordTypeApplicationData {
			t.Errorf("padLen %d: expected content type %d, got %d", padLen, RecordTypeApplicationData, ct)
		}
		if !bytes.Equal(pt, payload) {
			t.Errorf("padLen %d: plaintext mismatch", padLen)
		}
	}
}

func TestRecordLayer_CorruptedRecord(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("123456789012")

	newPair := func() (*RecordCipher, *RecordCipher) {
		s, err := NewRecordCipher(key, iv)
		if err != nil {
			t.Fatalf("NewRecordCipher sender: %v", err)
		}
		r, err := NewRecordCipher(key, iv)
		if err != nil {
			t.Fatalf("NewRecordCipher receiver: %v", err)
		}
		return s, r
	}

	payload := []byte("payload to corrupt")

	// 1. Truncated records
	t.Run("TruncatedRecord", func(t *testing.T) {
		_, receiver := newPair()
		truncatedLengths := []int{0, 1, 4, RecordHeaderLen, RecordHeaderLen + GCMTagSize}
		for _, tl := range truncatedLengths {
			buf := make([]byte, tl)
			if _, _, err := receiver.Unseal(buf); !errors.Is(err, ErrRecordTooShort) {
				t.Errorf("len %d: expected ErrRecordTooShort, got %v", tl, err)
			}
		}
	})

	// 2. Tampered outer header: opaque type
	t.Run("TamperedOpaqueType", func(t *testing.T) {
		sender, receiver := newPair()
		rec, err := sender.Seal(RecordTypeApplicationData, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		rec[0] = 22 // Tamper opaque type to Handshake (should be 23 in TLS 1.3)
		if _, _, err := receiver.Unseal(rec); !errors.Is(err, ErrInvalidRecordHeader) {
			t.Fatalf("expected ErrInvalidRecordHeader, got %v", err)
		}
	})

	// 3. Tampered outer header: legacy record version
	t.Run("TamperedLegacyVersion", func(t *testing.T) {
		sender, receiver := newPair()
		rec, err := sender.Seal(RecordTypeApplicationData, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		rec[1] = 0x03
		rec[2] = 0x04 // Change 0x0303 to 0x0304
		if _, _, err := receiver.Unseal(rec); !errors.Is(err, ErrInvalidRecordHeader) {
			t.Fatalf("expected ErrInvalidRecordHeader, got %v", err)
		}
	})

	// 4. Tampered outer header: length mismatch
	t.Run("TamperedLengthMismatch", func(t *testing.T) {
		sender, receiver := newPair()
		rec, err := sender.Seal(RecordTypeApplicationData, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		rec[4] ^= 0x01 // Modify length
		if _, _, err := receiver.Unseal(rec); !errors.Is(err, ErrRecordLengthMismatch) {
			t.Fatalf("expected ErrRecordLengthMismatch, got %v", err)
		}
	})

	// 5. Tampered ciphertext payload
	t.Run("TamperedCiphertext", func(t *testing.T) {
		sender, receiver := newPair()
		rec, err := sender.Seal(RecordTypeApplicationData, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		// Flip bit in ciphertext body (after 5-byte header)
		rec[RecordHeaderLen+2] ^= 0x55
		if _, _, err := receiver.Unseal(rec); err == nil {
			t.Fatalf("expected authentication failure on tampered ciphertext")
		}
	})

	// 6. Tampered GCM tag
	t.Run("TamperedTag", func(t *testing.T) {
		sender, receiver := newPair()
		rec, err := sender.Seal(RecordTypeApplicationData, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		// Flip bit in tag (last byte)
		rec[len(rec)-1] ^= 0x01
		if _, _, err := receiver.Unseal(rec); err == nil {
			t.Fatalf("expected authentication failure on tampered tag")
		}
	})
}

func TestRecordLayer_InvalidInputs(t *testing.T) {
	validKey := []byte("0123456789abcdef")
	validIV := []byte("123456789012")

	// Invalid key length
	for _, keyLen := range []int{0, 15, 17, 32} {
		k := make([]byte, keyLen)
		if _, err := NewRecordCipher(k, validIV); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("keyLen %d: expected ErrInvalidKeySize, got %v", keyLen, err)
		}
	}

	// Invalid IV length
	for _, ivLen := range []int{0, 8, 11, 13, 16} {
		iv := make([]byte, ivLen)
		if _, err := NewRecordCipher(validKey, iv); !errors.Is(err, ErrInvalidIVSize) {
			t.Errorf("ivLen %d: expected ErrInvalidIVSize, got %v", ivLen, err)
		}
	}

	rc, err := NewRecordCipher(validKey, validIV)
	if err != nil {
		t.Fatalf("NewRecordCipher: %v", err)
	}

	// Plaintext exceeds MaxPlaintextLength
	oversized := make([]byte, MaxPlaintextLength+1)
	if _, err := rc.Seal(RecordTypeApplicationData, oversized); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Errorf("expected ErrPlaintextTooLarge, got %v", err)
	}

	// Negative padding
	if _, err := rc.SealWithPadding(RecordTypeApplicationData, []byte("test"), -1); err == nil {
		t.Errorf("expected error for negative padding")
	}

	// Combined payload and padding exceeds MaxCiphertextLength
	largePlaintext := make([]byte, MaxPlaintextLength)
	if _, err := rc.SealWithPadding(RecordTypeApplicationData, largePlaintext, 300); err == nil {
		t.Errorf("expected error when ciphertext exceeds MaxCiphertextLength")
	}
}

func TestRecordLayer_DifferentRecordTypes(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("123456789012")

	sender, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher sender: %v", err)
	}
	receiver, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher receiver: %v", err)
	}

	testCases := []struct {
		recordType RecordType
		data       []byte
	}{
		{RecordTypeChangeCipherSpec, []byte{0x01}},
		{RecordTypeAlert, []byte{0x02, 0x0a}},
		{RecordTypeHandshake, []byte{0x01, 0x00, 0x00, 0x08, 0xaa, 0xbb, 0xcc, 0xdd}},
		{RecordTypeApplicationData, []byte("confidential application data")},
	}

	for _, tc := range testCases {
		rec, err := sender.Seal(tc.recordType, tc.data)
		if err != nil {
			t.Fatalf("seal type %d: %v", tc.recordType, err)
		}
		gotType, gotData, err := receiver.Unseal(rec)
		if err != nil {
			t.Fatalf("unseal type %d: %v", tc.recordType, err)
		}
		if gotType != tc.recordType {
			t.Errorf("expected type %d, got %d", tc.recordType, gotType)
		}
		if !bytes.Equal(gotData, tc.data) {
			t.Errorf("data mismatch for type %d", tc.recordType)
		}
	}
}

func TestRecordLayer_ResetAndSequence(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("123456789012")

	rc, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher: %v", err)
	}

	if rc.Sequence() != 0 {
		t.Errorf("expected initial sequence 0, got %d", rc.Sequence())
	}

	payload := []byte("ping")
	rec1, err := rc.Seal(RecordTypeApplicationData, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if rc.Sequence() != 1 {
		t.Errorf("expected sequence 1 after seal, got %d", rc.Sequence())
	}

	rc.Reset()
	if rc.Sequence() != 0 {
		t.Errorf("expected sequence 0 after reset, got %d", rc.Sequence())
	}

	// Now that sequence is reset, unsealing rec1 (which was sealed with seq 0) should succeed!
	ct, pt, err := rc.Unseal(rec1)
	if err != nil {
		t.Fatalf("unseal after reset: %v", err)
	}
	if ct != RecordTypeApplicationData || !bytes.Equal(pt, payload) {
		t.Errorf("payload mismatch after reset")
	}
	if rc.Sequence() != 1 {
		t.Errorf("expected sequence 1 after unseal, got %d", rc.Sequence())
	}
}

func TestRecordLayer_EmptyPayload(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("123456789012")

	sender, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher sender: %v", err)
	}
	receiver, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher receiver: %v", err)
	}

	// Empty payload with application data
	emptyPayload := []byte{}
	record, err := sender.Seal(RecordTypeApplicationData, emptyPayload)
	if err != nil {
		t.Fatalf("Seal empty: %v", err)
	}

	ct, pt, err := receiver.Unseal(record)
	if err != nil {
		t.Fatalf("Unseal empty: %v", err)
	}
	if ct != RecordTypeApplicationData {
		t.Errorf("expected RecordTypeApplicationData, got %d", ct)
	}
	if len(pt) != 0 {
		t.Errorf("expected 0-length plaintext, got %d", len(pt))
	}
}
