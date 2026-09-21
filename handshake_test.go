package teetls

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
)

func newTestCiphers(t *testing.T) (*RecordCipher, *RecordCipher) {
	t.Helper()
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
	return sender, receiver
}

func TestEncryptedHandshakeReader_CoalescedMessages(t *testing.T) {
	sender, receiver := newTestCiphers(t)

	msg1 := encodeHandshakeMsg(HandshakeTypeEncryptedExtensions, []byte{0x01})
	msg2 := encodeHandshakeMsg(HandshakeTypeCertificate, []byte("dummy-certificate-content"))
	msg3 := encodeHandshakeMsg(HandshakeTypeFinished, []byte("01234567890123456789012345678901"))

	coalesced := append(append(msg1, msg2...), msg3...)

	record, err := sender.Seal(RecordTypeHandshake, coalesced)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	r := bytes.NewReader(record)
	reader := newEncryptedHandshakeReader(r, receiver)

	// Read first message: EncryptedExtensions
	mType, body, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg 1 failed: %v", err)
	}
	if mType != HandshakeTypeEncryptedExtensions || !bytes.Equal(body, []byte{0x01}) {
		t.Fatalf("unexpected msg 1: type=%d, body=%x", mType, body)
	}

	// Read second message: Certificate
	mType, body, err = reader.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg 2 failed: %v", err)
	}
	if mType != HandshakeTypeCertificate || !bytes.Equal(body, []byte("dummy-certificate-content")) {
		t.Fatalf("unexpected msg 2: type=%d, body=%s", mType, string(body))
	}

	// Read third message: Finished
	mType, body, err = reader.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg 3 failed: %v", err)
	}
	if mType != HandshakeTypeFinished || !bytes.Equal(body, []byte("01234567890123456789012345678901")) {
		t.Fatalf("unexpected msg 3: type=%d, body=%s", mType, string(body))
	}

	if reader.HasRemaining() {
		t.Fatalf("expected HasRemaining=false, got true")
	}
}

func TestEncryptedHandshakeReader_FragmentedAcrossRecords(t *testing.T) {
	sender, receiver := newTestCiphers(t)

	largePayload := make([]byte, 5000)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}
	fullMsg := encodeHandshakeMsg(HandshakeTypeCertificate, largePayload)

	// Fragment across 3 records: 1500, 1500, remainder
	chunk1 := fullMsg[:1500]
	chunk2 := fullMsg[1500:3000]
	chunk3 := fullMsg[3000:]

	rec1, err := sender.Seal(RecordTypeHandshake, chunk1)
	if err != nil {
		t.Fatalf("Seal 1: %v", err)
	}
	rec2, err := sender.Seal(RecordTypeHandshake, chunk2)
	if err != nil {
		t.Fatalf("Seal 2: %v", err)
	}
	rec3, err := sender.Seal(RecordTypeHandshake, chunk3)
	if err != nil {
		t.Fatalf("Seal 3: %v", err)
	}

	stream := bytes.NewBuffer(nil)
	stream.Write(rec1)
	stream.Write(rec2)
	stream.Write(rec3)

	reader := newEncryptedHandshakeReader(stream, receiver)
	mType, body, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg failed: %v", err)
	}
	if mType != HandshakeTypeCertificate {
		t.Fatalf("expected type %d, got %d", HandshakeTypeCertificate, mType)
	}
	if !bytes.Equal(body, largePayload) {
		t.Fatalf("payload mismatch: got len %d, want %d", len(body), len(largePayload))
	}
	if reader.HasRemaining() {
		t.Fatalf("expected HasRemaining=false, got true")
	}
}

func TestEncryptedHandshakeReader_FragmentedAcrossHeader(t *testing.T) {
	sender, receiver := newTestCiphers(t)

	bodyData := []byte("handshake-body-fragment-test")
	fullMsg := encodeHandshakeMsg(HandshakeTypeCertificateVerify, bodyData)

	// Split so the 4-byte header is cut in half (2 bytes in rec1, 2 bytes + body in rec2)
	rec1, err := sender.Seal(RecordTypeHandshake, fullMsg[:2])
	if err != nil {
		t.Fatalf("Seal 1: %v", err)
	}
	rec2, err := sender.Seal(RecordTypeHandshake, fullMsg[2:])
	if err != nil {
		t.Fatalf("Seal 2: %v", err)
	}

	stream := bytes.NewBuffer(nil)
	stream.Write(rec1)
	stream.Write(rec2)

	reader := newEncryptedHandshakeReader(stream, receiver)
	mType, body, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg failed: %v", err)
	}
	if mType != HandshakeTypeCertificateVerify {
		t.Fatalf("expected type %d, got %d", HandshakeTypeCertificateVerify, mType)
	}
	if !bytes.Equal(body, bodyData) {
		t.Fatalf("body mismatch: got %s, want %s", string(body), string(bodyData))
	}
	if reader.HasRemaining() {
		t.Fatalf("expected HasRemaining=false, got true")
	}
}

func TestEncryptedHandshakeReader_CoalescedAndFragmented(t *testing.T) {
	sender, receiver := newTestCiphers(t)

	msgA := encodeHandshakeMsg(HandshakeTypeEncryptedExtensions, []byte{0x00})
	msgBBody := make([]byte, 2000)
	for i := range msgBBody {
		msgBBody[i] = byte(i)
	}
	msgB := encodeHandshakeMsg(HandshakeTypeCertificate, msgBBody)
	msgC := encodeHandshakeMsg(HandshakeTypeFinished, []byte("finished-mac-tag-32-bytes-long"))

	allBytes := append(append(msgA, msgB...), msgC...)

	// Split into two TLS records right in the middle of Message B
	splitPoint := len(msgA) + 800
	rec1, err := sender.Seal(RecordTypeHandshake, allBytes[:splitPoint])
	if err != nil {
		t.Fatalf("Seal 1: %v", err)
	}
	rec2, err := sender.Seal(RecordTypeHandshake, allBytes[splitPoint:])
	if err != nil {
		t.Fatalf("Seal 2: %v", err)
	}

	stream := bytes.NewBuffer(nil)
	stream.Write(rec1)
	stream.Write(rec2)

	reader := newEncryptedHandshakeReader(stream, receiver)

	// Message A
	mA, bA, err := reader.ReadMsg()
	if err != nil || mA != HandshakeTypeEncryptedExtensions || !bytes.Equal(bA, []byte{0x00}) {
		t.Fatalf("Msg A mismatch: err=%v, type=%d", err, mA)
	}

	// Message B
	mB, bB, err := reader.ReadMsg()
	if err != nil || mB != HandshakeTypeCertificate || !bytes.Equal(bB, msgBBody) {
		t.Fatalf("Msg B mismatch: err=%v, type=%d", err, mB)
	}

	// Message C
	mC, bC, err := reader.ReadMsg()
	if err != nil || mC != HandshakeTypeFinished || !bytes.Equal(bC, []byte("finished-mac-tag-32-bytes-long")) {
		t.Fatalf("Msg C mismatch: err=%v, type=%d", err, mC)
	}

	if reader.HasRemaining() {
		t.Fatalf("unexpected trailing data in reader")
	}
}

func TestEncryptedHandshakeReader_BufferLimitExceeded(t *testing.T) {
	sender, receiver := newTestCiphers(t)

	// Send chunks that declare a valid handshake message length, but cumulatively
	// exceed maxHandshakeBufferSize.
	fakeHeader := make([]byte, 4)
	fakeHeader[0] = HandshakeTypeCertificate
	// Declare length 3MB (exceeds maxHandshakeBufferSize of 2MB)
	msgLen := 3 * 1024 * 1024
	fakeHeader[1] = byte(msgLen >> 16)
	fakeHeader[2] = byte(msgLen >> 8)
	fakeHeader[3] = byte(msgLen)

	rec, err := sender.Seal(RecordTypeHandshake, fakeHeader)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	reader := newEncryptedHandshakeReader(bytes.NewReader(rec), receiver)
	_, _, err = reader.ReadMsg()
	if err == nil || !strings.Contains(err.Error(), "exceeds buffer limit") {
		t.Fatalf("expected buffer limit error, got: %v", err)
	}
}

func TestEncryptedHandshakeReader_TrailingDataDetection(t *testing.T) {
	sender, receiver := newTestCiphers(t)

	msg := encodeHandshakeMsg(HandshakeTypeFinished, []byte("tag32"))
	withTrailing := append(msg, []byte("trailing-garbage")...)

	rec, err := sender.Seal(RecordTypeHandshake, withTrailing)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	reader := newEncryptedHandshakeReader(bytes.NewReader(rec), receiver)
	mType, body, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if mType != HandshakeTypeFinished || !bytes.Equal(body, []byte("tag32")) {
		t.Fatalf("unexpected message: %d, %s", mType, string(body))
	}

	if !reader.HasRemaining() {
		t.Fatalf("expected HasRemaining=true for trailing data")
	}
}

func TestReadPlaintextHandshakeMsg_FragmentationAndReassembly(t *testing.T) {
	// Generate a message and fragment it across 2 plaintext records
	payload := []byte("ServerHello-fragmented-payload-test")
	fullMsg := encodeHandshakeMsg(HandshakeTypeServerHello, payload)

	buf := bytes.NewBuffer(nil)

	// Record 1 (first 10 bytes)
	rec1 := make([]byte, RecordHeaderLen+10)
	rec1[0] = byte(RecordTypeHandshake)
	rec1[1] = 0x03
	rec1[2] = 0x03
	binary.BigEndian.PutUint16(rec1[3:5], 10)
	copy(rec1[RecordHeaderLen:], fullMsg[:10])
	buf.Write(rec1)

	// Record 2 (remaining bytes)
	rem := len(fullMsg) - 10
	rec2 := make([]byte, RecordHeaderLen+rem)
	rec2[0] = byte(RecordTypeHandshake)
	rec2[1] = 0x03
	rec2[2] = 0x03
	binary.BigEndian.PutUint16(rec2[3:5], uint16(rem))
	copy(rec2[RecordHeaderLen:], fullMsg[10:])
	buf.Write(rec2)

	mType, body, wire, err := readPlaintextHandshakeMsg(buf)
	if err != nil {
		t.Fatalf("readPlaintextHandshakeMsg failed: %v", err)
	}
	if mType != HandshakeTypeServerHello {
		t.Fatalf("expected type %d, got %d", HandshakeTypeServerHello, mType)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body mismatch: got %s, want %s", string(body), string(payload))
	}
	if !bytes.Equal(wire, fullMsg) {
		t.Fatalf("wire mismatch")
	}
}

func TestHandshake_CoalescedServerMessages_EndToEnd(t *testing.T) {
	// Test full client and server handshake where encrypted server messages
	// (EncryptedExtensions, Certificate, CertificateVerify, Finished)
	// are coalesced into a single encrypted record via a custom buffered pipe wrapper.
	mockProv := NewMockEvidenceProvider()
	serverCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
	}
	clientCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
		ExpectedMeasurements: []string{
			mockProv.GetMeasurementHex(),
		},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := ServerHandshake(serverConn, serverCfg)
		errCh <- err
	}()

	go func() {
		defer wg.Done()
		_, err := ClientHandshake(clientConn, clientCfg)
		errCh <- err
	}()

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("handshake error: %v", err)
		}
	}
}
