package teetls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// shortWriter reports a short write with a nil error, exercising the writeFull
// defence against non-conforming net.Conn implementations.
type shortWriter struct {
	done bool
}

func (s *shortWriter) Write(p []byte) (int, error) {
	if !s.done {
		s.done = true
		return len(p) - 1, nil
	}
	return len(p), nil
}

func TestWriteFull(t *testing.T) {
	buf := &bytes.Buffer{}
	if err := writeFull(buf, []byte("hello")); err != nil {
		t.Fatalf("writeFull(full) error = %v, want nil", err)
	}
	if buf.String() != "hello" {
		t.Fatalf("writeFull(full) wrote %q, want %q", buf.String(), "hello")
	}

	short := &shortWriter{}
	if err := writeFull(short, []byte("hello")); err != io.ErrShortWrite {
		t.Fatalf("writeFull(short) error = %v, want io.ErrShortWrite", err)
	}
}

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

// coalescingConn delays everything written to it until the wrapped side is about
// to read, so that records written one at a time by the handshake arrive at the
// peer as a single contiguous stream. net.Pipe is synchronous and unbuffered, so
// without a wrapper like this each Write is delivered to its own Read and record
// coalescing can never be exercised.
type coalescingConn struct {
	net.Conn

	mu      sync.Mutex
	pending []byte
	// writes counts the Write calls accumulated since the last flush.
	writes int
	// flushes records, in order, the byte chunks handed to the underlying
	// connection together with the number of Write calls each one coalesced.
	flushes []flushBatch
}

type flushBatch struct {
	data   []byte
	writes int
}

func (c *coalescingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, p...)
	c.writes++
	return len(p), nil
}

func (c *coalescingConn) Read(p []byte) (int, error) {
	if err := c.flush(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// flush hands the buffered bytes to the underlying connection in a single Write.
func (c *coalescingConn) flush() error {
	c.mu.Lock()
	batch := flushBatch{data: c.pending, writes: c.writes}
	c.pending = nil
	c.writes = 0
	if len(batch.data) > 0 {
		c.flushes = append(c.flushes, batch)
	}
	c.mu.Unlock()

	if len(batch.data) == 0 {
		return nil
	}
	_, err := c.Conn.Write(batch.data)
	return err
}

// countRecords returns the number of complete TLS records at the start of b.
func countRecords(b []byte) int {
	n := 0
	for len(b) >= RecordHeaderLen {
		length := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < RecordHeaderLen+length {
			break
		}
		b = b[RecordHeaderLen+length:]
		n++
	}
	return n
}

func TestHandshake_CoalescedServerMessages_EndToEnd(t *testing.T) {
	// Full client and server handshake where the server's encrypted flight
	// (EncryptedExtensions, Certificate, CertificateVerify, Finished) is written
	// as separate records but delivered to the client as one contiguous chunk.
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

	clientConn, rawServerConn := net.Pipe()
	defer clientConn.Close()
	defer rawServerConn.Close()

	serverConn := &coalescingConn{Conn: rawServerConn}

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

	// The server must have batched several record writes into its first flush.
	// If it had not, the client would only ever have seen one record at a time
	// and the reader's coalescing path would be untested.
	serverConn.mu.Lock()
	flushes := append([]flushBatch(nil), serverConn.flushes...)
	serverConn.mu.Unlock()

	if len(flushes) == 0 {
		t.Fatal("server never wrote anything through the coalescing connection")
	}
	first := flushes[0]
	if first.writes < 2 {
		t.Fatalf("first server flush coalesced %d Write call(s), want at least 2", first.writes)
	}
	if records := countRecords(first.data); records < 2 {
		t.Fatalf("first server flush carried %d complete record(s), want at least 2", records)
	}

	// Whatever the batching, the whole session must still have been delivered.
	total := 0
	for _, f := range flushes {
		total += countRecords(f.data)
	}
	if total < 2 {
		t.Fatalf("server wrote %d record(s) in total, want at least 2", total)
	}
}

// flagFlipConn rewrites the mutual-attestation flag byte in the plaintext
// ClientHello it forwards, simulating an on-path attacker clearing the client's
// request to attest itself. The flag travels outside the authenticated
// transcript, so the flip is undetectable until the server's authenticated
// EncryptedExtensions fails to echo mutual attestation back.
type flagFlipConn struct {
	net.Conn
	flipped bool
}

func (c *flagFlipConn) Write(p []byte) (int, error) {
	if !c.flipped && len(p) > RecordHeaderLen &&
		p[0] == byte(RecordTypeHandshake) && p[RecordHeaderLen] == HandshakeTypeClientHello {
		c.flipped = true
		buf := append([]byte(nil), p...)
		// The mutual-attestation flag is the final byte of the ClientHello record.
		buf[len(buf)-1] = 0
		_, err := c.Conn.Write(buf)
		return len(p), err
	}
	return c.Conn.Write(p)
}

// TestMutualAttestationDowngradeRejected verifies that a client which asked to
// attest itself rejects the handshake when an on-path attacker clears the
// plaintext mutual-attestation flag and the server therefore fails to require
// client attestation in its authenticated EncryptedExtensions.
func TestMutualAttestationDowngradeRejected(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	serverCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
	}
	clientCfg := &Config{
		Mode:                    ModeStrict,
		EvidenceProvider:        mockProv,
		VerifyMutualAttestation: true,
		ExpectedMeasurements:    []string{mockProv.GetMeasurementHex()},
	}

	clientConn, rawServerConn := net.Pipe()
	defer rawServerConn.Close()

	// The client's ClientHello passes through flagFlipConn, so the server sees
	// the mutual-attestation flag cleared and omits mutual from its
	// EncryptedExtensions.
	clientConn = &flagFlipConn{Conn: clientConn}
	defer clientConn.Close()

	serverDone := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(rawServerConn, serverCfg)
		serverDone <- err
	}()

	_, err := ClientHandshake(clientConn, clientCfg)
	if !errors.Is(err, ErrMutualAttestationNotConfirmed) {
		t.Fatalf("client error = %v, want ErrMutualAttestationNotConfirmed", err)
	}

	// Closing the client end unblocks the server, which is waiting for a Finished
	// message the downgrade-rejecting client will never send.
	clientConn.Close()
	<-serverDone
}

// deadlineRecordingConn records every deadline the handshake applies to a
// connection, so that the tests can assert on the bound without depending on how
// long the (comparatively expensive) SM2 and SM3 work happens to take.
type deadlineRecordingConn struct {
	net.Conn

	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineRecordingConn) recordedDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

// TestServerHandshakeContext_StalledPeerTimesOut verifies that a peer which
// connects and then sends nothing cannot hold the server goroutine open beyond
// Config.Timeout.
func TestServerHandshakeContext_StalledPeerTimesOut(t *testing.T) {
	// Comfortably longer than the server's certificate preparation, so that what
	// is measured below is the blocked read of the ClientHello and not an
	// earlier failure.
	timeout := time.Second
	mockProv := NewMockEvidenceProvider()
	cfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
		Timeout:          timeout,
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := ServerHandshakeContext(context.Background(), serverConn, cfg)
		done <- err
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected the stalled handshake to fail, got nil error")
		}
		if elapsed < timeout {
			t.Fatalf("handshake gave up after %v, before Config.Timeout of %v", elapsed, timeout)
		}
		if elapsed > 20*timeout {
			t.Fatalf("handshake took %v, far beyond Config.Timeout of %v", elapsed, timeout)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("ServerHandshakeContext did not return; the handshake is not bounded by Config.Timeout")
	}
}

// TestServerHandshakeContext_DeadlineLifecycle verifies that the server bounds
// the handshake with a deadline and then clears it, and that application data
// flows afterwards.
//
// The deadline is asserted on directly rather than by sleeping past Config.Timeout:
// a sleep would have to outlast the handshake itself, which is slow enough under
// the race detector to make the test flaky.
func TestServerHandshakeContext_DeadlineLifecycle(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	serverCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
		Timeout:          60 * time.Second,
	}
	clientCfg := &Config{
		Mode:                 ModeStrict,
		EvidenceProvider:     mockProv,
		Timeout:              60 * time.Second,
		ExpectedMeasurements: []string{mockProv.GetMeasurementHex()},
	}

	clientConn, rawServerConn := net.Pipe()
	defer clientConn.Close()
	defer rawServerConn.Close()
	serverConn := &deadlineRecordingConn{Conn: rawServerConn}

	type result struct {
		res *HandshakeResult
		err error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		res, err := ServerHandshakeContext(context.Background(), serverConn, serverCfg)
		serverCh <- result{res, err}
	}()
	go func() {
		res, err := ClientHandshakeContext(context.Background(), clientConn, clientCfg)
		clientCh <- result{res, err}
	}()

	// Both handshakes must finish. Bound the waits so that a failure reports
	// itself instead of hanging the suite.
	var server, client result
	for i := 0; i < 2; i++ {
		select {
		case server = <-serverCh:
			serverCh = nil
		case client = <-clientCh:
			clientCh = nil
		case <-time.After(60 * time.Second):
			t.Fatal("handshake did not complete; the deadline may be cutting it short")
		}
	}
	if server.err != nil {
		t.Fatalf("server handshake error: %v", server.err)
	}
	if client.err != nil {
		t.Fatalf("client handshake error: %v", client.err)
	}

	// The server must have bounded the handshake with a real deadline...
	deadlines := serverConn.recordedDeadlines()
	if len(deadlines) == 0 {
		t.Fatal("server handshake never set a deadline on the connection")
	}
	if deadlines[0].IsZero() {
		t.Fatal("server handshake did not bound itself with a deadline")
	}
	// ...and cleared it again, so that no handshake deadline is left behind on a
	// connection that is about to carry application data.
	if last := deadlines[len(deadlines)-1]; !last.IsZero() {
		t.Fatalf("server handshake left deadline %v on the connection, want it cleared", last)
	}

	// Application data must flow over the finished connection.
	payload := []byte("application data after the handshake")
	record, err := client.res.OutCipher.Seal(RecordTypeApplicationData, payload)
	if err != nil {
		t.Fatalf("seal application data: %v", err)
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(record)
		writeErr <- err
	}()

	buf := make([]byte, len(record))
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatalf("read application data after the handshake: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write application data after the handshake: %v", err)
	}

	contentType, got, err := server.res.InCipher.Unseal(buf)
	if err != nil {
		t.Fatalf("unseal application data: %v", err)
	}
	if contentType != RecordTypeApplicationData {
		t.Fatalf("content type = %d, want %d", contentType, RecordTypeApplicationData)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}
