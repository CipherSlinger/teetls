package teetls

import (
	"context"
	cx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Conn implements a net.Conn secured by RFC 8998 TLS 1.3 with CSV hardware attestation.
type Conn struct {
	rawConn  net.Conn
	cfg      *Config
	isServer bool

	handshakeDone  atomic.Bool
	handshakeMutex sync.Mutex
	handshakeErr   error

	inCipher  *RecordCipher
	outCipher *RecordCipher

	peerMu          sync.RWMutex
	peerCertPEM     []byte
	peerEvidence    *CSVEvidenceExtension
	peerCertificate *cx509.Certificate

	readBuf             []byte
	readMu              sync.Mutex
	writeMu             sync.Mutex
	closeNotifyReceived atomic.Bool

	closeOnce sync.Once
	closeErr  error
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
	return c.handshake(context.Background())
}

func (c *Conn) handshake(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
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
		res, err = ServerHandshakeContext(ctx, c.rawConn, c.cfg)
	} else {
		res, err = ClientHandshakeContext(ctx, c.rawConn, c.cfg)
	}

	if err != nil {
		c.handshakeErr = err
		return err
	}

	c.inCipher = res.InCipher
	c.outCipher = res.OutCipher
	c.peerMu.Lock()
	c.peerCertPEM = append([]byte(nil), res.PeerCertPEM...)
	c.peerEvidence = cloneEvidence(res.PeerEvidence)
	if res.PeerCertificate != nil {
		c.peerCertificate = res.PeerCertificate.ToX509Certificate()
	}
	c.peerMu.Unlock()

	c.handshakeDone.Store(true)
	return nil
}

// Read reads decrypted application data from the connection.
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
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
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if c.closeNotifyReceived.Load() {
					return 0, io.EOF
				}
				return 0, fmt.Errorf("teetls: connection closed without close_notify: %w", io.ErrUnexpectedEOF)
			}
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
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, fmt.Errorf("teetls: truncated TLS record without close_notify: %w", io.ErrUnexpectedEOF)
			}
			return 0, err
		}

		recType, plaintext, err := c.inCipher.Unseal(fullRecord)
		if err != nil {
			return 0, fmt.Errorf("teetls: unseal record: %w", err)
		}

		if recType == RecordTypeAlert {
			if len(plaintext) != 2 {
				return 0, fmt.Errorf("teetls: malformed alert length %d", len(plaintext))
			}
			level, desc := plaintext[0], plaintext[1]
			if level == 1 && desc == 0 {
				c.closeNotifyReceived.Store(true)
				return 0, io.EOF
			}
			return 0, fmt.Errorf("teetls: received alert (level %d, desc %d)", level, desc)
		}

		if recType != RecordTypeApplicationData {
			return 0, fmt.Errorf("teetls: unexpected post-handshake record type %d", recType)
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
	c.closeOnce.Do(func() {
		var alertErr error
		if c.handshakeDone.Load() && c.outCipher != nil {
			c.writeMu.Lock()
			alertPayload := []byte{1, 0}
			record, err := c.outCipher.Seal(RecordTypeAlert, alertPayload)
			if err != nil {
				alertErr = fmt.Errorf("teetls: seal close_notify: %w", err)
			} else {
				if err := c.rawConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
					alertErr = fmt.Errorf("teetls: set close_notify deadline: %w", err)
				} else if _, err := c.rawConn.Write(record); err != nil {
					alertErr = fmt.Errorf("teetls: write close_notify: %w", err)
				}
			}
			c.writeMu.Unlock()
		}
		c.closeErr = errors.Join(alertErr, c.rawConn.Close())
	})
	return c.closeErr
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
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()
	return cloneEvidence(c.peerEvidence)
}

// PeerCertificate returns the peer's parsed X.509 certificate.
func (c *Conn) PeerCertificate() *cx509.Certificate {
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()
	if c.peerCertificate == nil {
		return nil
	}
	cert := *c.peerCertificate
	cert.Raw = append([]byte(nil), c.peerCertificate.Raw...)
	cert.RawTBSCertificate = append([]byte(nil), c.peerCertificate.RawTBSCertificate...)
	cert.RawSubjectPublicKeyInfo = append([]byte(nil), c.peerCertificate.RawSubjectPublicKeyInfo...)
	cert.RawSubject = append([]byte(nil), c.peerCertificate.RawSubject...)
	cert.RawIssuer = append([]byte(nil), c.peerCertificate.RawIssuer...)
	cert.Signature = append([]byte(nil), c.peerCertificate.Signature...)
	cert.DNSNames = append([]string(nil), c.peerCertificate.DNSNames...)
	cert.EmailAddresses = append([]string(nil), c.peerCertificate.EmailAddresses...)
	cert.IPAddresses = append([]net.IP(nil), c.peerCertificate.IPAddresses...)
	cert.URIs = append([]*url.URL(nil), c.peerCertificate.URIs...)
	cert.ExtKeyUsage = append([]cx509.ExtKeyUsage(nil), c.peerCertificate.ExtKeyUsage...)
	cert.UnknownExtKeyUsage = append([]asn1.ObjectIdentifier(nil), c.peerCertificate.UnknownExtKeyUsage...)
	cert.Extensions = append([]pkix.Extension(nil), c.peerCertificate.Extensions...)
	cert.ExtraExtensions = append([]pkix.Extension(nil), c.peerCertificate.ExtraExtensions...)
	cert.UnhandledCriticalExtensions = append([]asn1.ObjectIdentifier(nil), c.peerCertificate.UnhandledCriticalExtensions...)
	cert.PolicyIdentifiers = append([]asn1.ObjectIdentifier(nil), c.peerCertificate.PolicyIdentifiers...)
	cert.PermittedDNSDomains = append([]string(nil), c.peerCertificate.PermittedDNSDomains...)
	cert.ExcludedDNSDomains = append([]string(nil), c.peerCertificate.ExcludedDNSDomains...)
	cert.PermittedEmailAddresses = append([]string(nil), c.peerCertificate.PermittedEmailAddresses...)
	cert.ExcludedEmailAddresses = append([]string(nil), c.peerCertificate.ExcludedEmailAddresses...)
	cert.PermittedURIDomains = append([]string(nil), c.peerCertificate.PermittedURIDomains...)
	cert.ExcludedURIDomains = append([]string(nil), c.peerCertificate.ExcludedURIDomains...)
	return &cert
}

// PeerCertPEM returns the peer's raw PEM-encoded certificate.
func (c *Conn) PeerCertPEM() []byte {
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()
	return append([]byte(nil), c.peerCertPEM...)
}

func cloneEvidence(ev *CSVEvidenceExtension) *CSVEvidenceExtension {
	if ev == nil {
		return nil
	}
	return &CSVEvidenceExtension{
		Version:    ev.Version,
		Report:     append([]byte(nil), ev.Report...),
		HRKCert:    append([]byte(nil), ev.HRKCert...),
		HSKCekCert: append([]byte(nil), ev.HSKCekCert...),
	}
}

// Ensure Conn implements net.Conn at compile time.
var _ net.Conn = (*Conn)(nil)
