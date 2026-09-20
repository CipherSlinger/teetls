package teetls

import (
	cx509 "crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Conn implements a net.Conn secured by RFC 8998 TLS 1.3 with CSV hardware attestation.
type Conn struct {
	rawConn net.Conn
	cfg     *Config
	isServer bool

	handshakeDone  atomic.Bool
	handshakeMutex sync.Mutex
	handshakeErr   error

	inCipher  *RecordCipher
	outCipher *RecordCipher

	peerCertPEM     []byte
	peerEvidence    *CSVEvidenceExtension
	peerCertificate *cx509.Certificate

	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex

	closeOnce sync.Once
}

// NewClientConn wraps an existing net.Conn as a client TEE-TLS connection.
func NewClientConn(rawConn net.Conn, cfg *Config) *Conn {
	return &Conn{
		rawConn:  rawConn,
		cfg:      cfg,
		isServer: false,
	}
}

// NewServerConn wraps an existing net.Conn as a server TEE-TLS connection.
func NewServerConn(rawConn net.Conn, cfg *Config) *Conn {
	return &Conn{
		rawConn:  rawConn,
		cfg:      cfg,
		isServer: true,
	}
}

// Handshake executes the RFC 8998 handshake if not already completed.
func (c *Conn) Handshake() error {
	if c.handshakeDone.Load() {
		return nil
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.handshakeDone.Load() {
		return nil
	}
	if c.handshakeErr != nil {
		return c.handshakeErr
	}

	var res *HandshakeResult
	var err error
	if c.isServer {
		res, err = ServerHandshake(c.rawConn, c.cfg)
	} else {
		res, err = ClientHandshake(c.rawConn, c.cfg)
	}

	if err != nil {
		c.handshakeErr = err
		return err
	}

	c.inCipher = res.InCipher
	c.outCipher = res.OutCipher
	c.peerCertPEM = res.PeerCertPEM
	c.peerEvidence = res.PeerEvidence
	if res.PeerCertificate != nil {
		c.peerCertificate = res.PeerCertificate.ToX509Certificate()
	}

	c.handshakeDone.Store(true)
	return nil
}

// Read reads decrypted application data from the connection.
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	// 1. Drain any buffered decrypted plaintext from previous records
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// 2. Read next TLS record from rawConn
	for {
		header := make([]byte, RecordHeaderLen)
		if _, err := io.ReadFull(c.rawConn, header); err != nil {
			return 0, err
		}

		if header[0] != byte(RecordTypeApplicationData) {
			return 0, ErrInvalidRecordHeader
		}

		payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
		if payloadLen <= 0 || payloadLen > MaxCiphertextLength {
			return 0, ErrCiphertextTooLarge
		}

		fullRecord := make([]byte, RecordHeaderLen+payloadLen)
		copy(fullRecord[:RecordHeaderLen], header)
		if _, err := io.ReadFull(c.rawConn, fullRecord[RecordHeaderLen:]); err != nil {
			return 0, err
		}

		recType, plaintext, err := c.inCipher.Unseal(fullRecord)
		if err != nil {
			return 0, fmt.Errorf("teetls: unseal record: %w", err)
		}

		if recType == RecordTypeAlert {
			if len(plaintext) >= 2 && plaintext[1] == 0 {
				return 0, io.EOF
			}
			if len(plaintext) >= 2 {
				return 0, fmt.Errorf("teetls: received fatal alert (level %d, desc %d)", plaintext[0], plaintext[1])
			}
			return 0, io.EOF
		}

		if recType != RecordTypeApplicationData {
			// Ignore non-application data records or continue
			continue
		}

		if len(plaintext) == 0 {
			// Empty record, continue reading next record
			continue
		}

		n := copy(b, plaintext)
		if n < len(plaintext) {
			c.readBuf = make([]byte, len(plaintext)-n)
			copy(c.readBuf, plaintext[n:])
		}
		return n, nil
	}
}

// Write encrypts b as an ApplicationData record and writes it to the raw connection.
func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	totalSent := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > MaxPlaintextLength {
			chunkSize = MaxPlaintextLength
		}

		chunk := b[:chunkSize]
		record, err := c.outCipher.Seal(RecordTypeApplicationData, chunk)
		if err != nil {
			return totalSent, fmt.Errorf("teetls: seal record: %w", err)
		}

		if _, err := c.rawConn.Write(record); err != nil {
			return totalSent, err
		}

		totalSent += chunkSize
		b = b[chunkSize:]
	}

	return totalSent, nil
}

// Close closes the underlying raw connection, transmitting a close_notify alert if handshake succeeded.
func (c *Conn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		if c.handshakeDone.Load() && c.outCipher != nil {
			c.writeMu.Lock()
			// Alert record payload: Level (1 = warning), Description (0 = close_notify)
			alertPayload := []byte{1, 0}
			record, err := c.outCipher.Seal(RecordTypeAlert, alertPayload)
			if err == nil {
				_ = c.rawConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				_, _ = c.rawConn.Write(record)
			}
			c.writeMu.Unlock()
		}
		closeErr = c.rawConn.Close()
	})
	return closeErr
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.rawConn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.rawConn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.rawConn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.rawConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.rawConn.SetWriteDeadline(t)
}

// PeerEvidence returns the peer's CSV attestation evidence extension.
func (c *Conn) PeerEvidence() *CSVEvidenceExtension {
	return c.peerEvidence
}

// PeerCertificate returns the peer's parsed X.509 certificate.
func (c *Conn) PeerCertificate() *cx509.Certificate {
	return c.peerCertificate
}

// PeerCertPEM returns the peer's raw PEM-encoded certificate.
func (c *Conn) PeerCertPEM() []byte {
	return c.peerCertPEM
}

// Ensure Conn implements net.Conn at compile time.
var _ net.Conn = (*Conn)(nil)
