package teetls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	gx509 "github.com/tjfoc/gmsm/x509"
	"golang.org/x/crypto/hkdf"
)

// Handshake message types
const (
	HandshakeTypeClientHello         uint8 = 1
	HandshakeTypeServerHello         uint8 = 2
	HandshakeTypeEncryptedExtensions uint8 = 8
	HandshakeTypeCertificate         uint8 = 11
	HandshakeTypeCertificateVerify   uint8 = 15
	HandshakeTypeFinished            uint8 = 20
)

const (
	// HandshakeHeaderLen is 4 bytes: 1 byte msg_type + 3 bytes length.
	HandshakeHeaderLen = 4
	// SM2UncompressedPubKeyLen is 65 bytes (0x04 || X[32] || Y[32]).
	SM2UncompressedPubKeyLen = 65
	// RandomBytesLen is 32 bytes for client/server random.
	RandomBytesLen = 32
)

// HandshakeTrafficKeys holds the symmetric keys and IVs derived via HKDF-SM3 for the handshake phase.
type HandshakeTrafficKeys struct {
	ClientWriteKey    []byte // 16 bytes
	ClientWriteIV     []byte // 12 bytes
	ServerWriteKey    []byte // 16 bytes
	ServerWriteIV     []byte // 12 bytes
	ServerFinishedKey []byte // 32 bytes
	ClientFinishedKey []byte // 32 bytes
}

// HandshakeKeys is maintained as an alias to HandshakeTrafficKeys for compatibility.
type HandshakeKeys = HandshakeTrafficKeys

// ApplicationTrafficKeys holds distinct symmetric keys and IVs for application data traffic.
type ApplicationTrafficKeys struct {
	ClientWriteKey []byte // 16 bytes
	ClientWriteIV  []byte // 12 bytes
	ServerWriteKey []byte // 16 bytes
	ServerWriteIV  []byte // 12 bytes
}

// HandshakeResult holds peer attestation and certificate after a successful handshake.
type HandshakeResult struct {
	InCipher        *RecordCipher
	OutCipher       *RecordCipher
	PeerCertPEM     []byte
	PeerEvidence    *CSVEvidenceExtension
	PeerCertificate *gx509.Certificate
}

// ErrMutualAttestationRequired indicates the server requires client attestation credentials.
var ErrMutualAttestationRequired = errors.New("teetls: mutual attestation required")

// encodeHandshakeMsg packs a handshake message with a 4-byte header: type (1 byte) + length (3 bytes).
func encodeHandshakeMsg(msgType uint8, body []byte) []byte {
	length := len(body)
	header := []byte{
		msgType,
		byte((length >> 16) & 0xff),
		byte((length >> 8) & 0xff),
		byte(length & 0xff),
	}
	return append(header, body...)
}

// writePlaintextHandshakeMsg encapsulates a handshake message into a 5-byte TLSPlaintext record and writes it to w.
func writePlaintextHandshakeMsg(w io.Writer, msgType uint8, body []byte) ([]byte, error) {
	hsMsg := encodeHandshakeMsg(msgType, body)
	if len(hsMsg) > MaxPlaintextLength {
		return nil, errors.New("teetls: plaintext handshake message exceeds max record length")
	}

	record := make([]byte, RecordHeaderLen+len(hsMsg))
	record[0] = byte(RecordTypeHandshake)
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(hsMsg)))
	copy(record[RecordHeaderLen:], hsMsg)

	if _, err := w.Write(record); err != nil {
		return nil, fmt.Errorf("write plaintext handshake record: %w", err)
	}
	return hsMsg, nil
}

// maxHandshakeBufferSize limits the maximum buffered handshake data to prevent resource exhaustion.
const maxHandshakeBufferSize = 2 * 1024 * 1024

// readPlaintextHandshakeMsg reads a TLSPlaintext record from r and decodes the handshake message,
// assembling across multiple plaintext records if fragmented.
func readPlaintextHandshakeMsg(r io.Reader) (uint8, []byte, []byte, error) {
	var assembled []byte
	var msgType uint8
	var expectedTotalLen int

	for {
		header := make([]byte, RecordHeaderLen)
		if _, err := io.ReadFull(r, header); err != nil {
			return 0, nil, nil, fmt.Errorf("read plaintext record header: %w", err)
		}

		if header[0] != byte(RecordTypeHandshake) {
			return 0, nil, nil, fmt.Errorf("teetls: expected plaintext handshake record (22), got %d", header[0])
		}

		payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
		if payloadLen <= 0 || payloadLen > MaxPlaintextLength {
			return 0, nil, nil, fmt.Errorf("teetls: invalid plaintext handshake record payload length %d", payloadLen)
		}

		recordPayload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, recordPayload); err != nil {
			return 0, nil, nil, fmt.Errorf("read plaintext handshake payload: %w", err)
		}

		if len(assembled)+len(recordPayload) > maxHandshakeBufferSize {
			return 0, nil, nil, errors.New("teetls: plaintext handshake buffer size limit exceeded")
		}
		assembled = append(assembled, recordPayload...)

		if expectedTotalLen == 0 && len(assembled) >= HandshakeHeaderLen {
			msgType = assembled[0]
			msgLen := int(assembled[1])<<16 | int(assembled[2])<<8 | int(assembled[3])
			if msgLen < 0 || msgLen > 1<<24 {
				return 0, nil, nil, errors.New("teetls: invalid handshake message length")
			}
			expectedTotalLen = HandshakeHeaderLen + msgLen
		}

		if expectedTotalLen > 0 && len(assembled) >= expectedTotalLen {
			if len(assembled) > expectedTotalLen {
				return 0, nil, nil, errors.New("teetls: excess data in plaintext handshake fragment")
			}
			body := assembled[HandshakeHeaderLen:expectedTotalLen]
			return msgType, body, assembled, nil
		}
	}
}

// readHandshakeMsg reads exactly one handshake message from an io.Reader without TLS record framing.
func readHandshakeMsg(r io.Reader) (uint8, []byte, error) {
	header := make([]byte, HandshakeHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	msgType := header[0]
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length < 0 || length > 1<<24 {
		return 0, nil, errors.New("teetls: handshake message too large")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return msgType, body, nil
}

// encodePublicKeySM2 serializes an SM2 public key as 65 uncompressed bytes (0x04 || X[32] || Y[32]).
func encodePublicKeySM2(pub *sm2.PublicKey) []byte {
	raw := make([]byte, SM2UncompressedPubKeyLen)
	raw[0] = 0x04
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(raw[1+32-len(xBytes):1+32], xBytes)
	copy(raw[33+32-len(yBytes):33+32], yBytes)
	return raw
}

// decodePublicKeySM2 parses a 65-byte uncompressed point into an SM2 PublicKey.
func decodePublicKeySM2(raw []byte) (*sm2.PublicKey, error) {
	if len(raw) != SM2UncompressedPubKeyLen || raw[0] != 0x04 {
		return nil, errors.New("teetls: invalid SM2 uncompressed public key format")
	}
	curve := sm2.P256Sm2()
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("teetls: SM2 public key point not on curve")
	}
	return &sm2.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// computeECDHESharedSecret computes Z = Sx (32 bytes zero-padded) from peer public key and local private key.
func computeECDHESharedSecret(peerPub *sm2.PublicKey, priv *sm2.PrivateKey) ([]byte, error) {
	curve := sm2.P256Sm2()
	sx, _ := curve.ScalarMult(peerPub.X, peerPub.Y, priv.D.Bytes())
	if sx == nil {
		return nil, errors.New("teetls: scalar mult produced nil point")
	}
	sxBytes := sx.Bytes()
	z := make([]byte, 32)
	copy(z[32-len(sxBytes):], sxBytes)
	return z, nil
}

// extractSM2PublicKey extracts *sm2.PublicKey from x509.Certificate.PublicKey (which gx509 can return as *ecdsa.PublicKey or *sm2.PublicKey).
func extractSM2PublicKey(pubKey interface{}) (*sm2.PublicKey, error) {
	switch p := pubKey.(type) {
	case *sm2.PublicKey:
		return p, nil
	case *ecdsa.PublicKey:
		return &sm2.PublicKey{
			Curve: sm2.P256Sm2(),
			X:     p.X,
			Y:     p.Y,
		}, nil
	default:
		return nil, errors.New("teetls: peer certificate public key is not SM2/ECDSA")
	}
}

// deriveHandshakeTrafficKeys computes the RFC 8998 ShangMi TLS 1.3 handshake traffic keys using HKDF-SM3.
func deriveHandshakeTrafficKeys(sharedSecret, clientRandom, serverRandom []byte) (*HandshakeTrafficKeys, error) {
	salt := append(append([]byte{}, clientRandom...), serverRandom...)
	info := []byte("tls13-rfc8998-sm4-gcm-sm3-handshake")
	kdf := hkdf.New(sm3.New, sharedSecret, salt, info)

	keys := &HandshakeTrafficKeys{
		ClientWriteKey:    make([]byte, 16),
		ClientWriteIV:     make([]byte, 12),
		ServerWriteKey:    make([]byte, 16),
		ServerWriteIV:     make([]byte, 12),
		ServerFinishedKey: make([]byte, 32),
		ClientFinishedKey: make([]byte, 32),
	}

	if _, err := io.ReadFull(kdf, keys.ClientWriteKey); err != nil {
		return nil, fmt.Errorf("derive client handshake write key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ClientWriteIV); err != nil {
		return nil, fmt.Errorf("derive client handshake write iv: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerWriteKey); err != nil {
		return nil, fmt.Errorf("derive server handshake write key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerWriteIV); err != nil {
		return nil, fmt.Errorf("derive server handshake write iv: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerFinishedKey); err != nil {
		return nil, fmt.Errorf("derive server finished key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ClientFinishedKey); err != nil {
		return nil, fmt.Errorf("derive client finished key: %w", err)
	}

	return keys, nil
}

// deriveApplicationTrafficKeys computes distinct symmetric keys for application data traffic.
func deriveApplicationTrafficKeys(sharedSecret, transcriptHash []byte) (*ApplicationTrafficKeys, error) {
	info := []byte("tls13-rfc8998-sm4-gcm-sm3-application")
	kdf := hkdf.New(sm3.New, sharedSecret, transcriptHash, info)

	keys := &ApplicationTrafficKeys{
		ClientWriteKey: make([]byte, 16),
		ClientWriteIV:  make([]byte, 12),
		ServerWriteKey: make([]byte, 16),
		ServerWriteIV:  make([]byte, 12),
	}

	if _, err := io.ReadFull(kdf, keys.ClientWriteKey); err != nil {
		return nil, fmt.Errorf("derive client app write key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ClientWriteIV); err != nil {
		return nil, fmt.Errorf("derive client app write iv: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerWriteKey); err != nil {
		return nil, fmt.Errorf("derive server app write key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerWriteIV); err != nil {
		return nil, fmt.Errorf("derive server app write iv: %w", err)
	}

	return keys, nil
}

// deriveKeys is kept for backward compatibility, returning handshake keys.
func deriveKeys(sharedSecret, clientRandom, serverRandom []byte) (*HandshakeTrafficKeys, error) {
	return deriveHandshakeTrafficKeys(sharedSecret, clientRandom, serverRandom)
}

// computeHMACSM3 calculates HMAC-SM3 over the input data using the given key.
func computeHMACSM3(key, data []byte) []byte {
	mac := hmac.New(sm3.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// prepareServerCertificate resolves or generates server SM2 certificate and private key.
func prepareServerCertificate(cfg *Config) (certPEM []byte, privKey *sm2.PrivateKey, err error) {
	return prepareServerCertificateContext(context.Background(), cfg)
}

func prepareServerCertificateContext(ctx context.Context, cfg *Config) (certPEM []byte, privKey *sm2.PrivateKey, err error) {
	certPEM, keyPEM, err := cfg.GetOrGenerateCertificateContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare server certificate: %w", err)
	}
	priv, err := gx509.ReadPrivateKeyFromPem(keyPEM, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("read server private key: %w", err)
	}
	return certPEM, priv, nil
}

// prepareClientCertificate resolves or generates client SM2 certificate and private key for mutual attestation.
func prepareClientCertificate(cfg *Config) (certPEM []byte, privKey *sm2.PrivateKey, err error) {
	return prepareClientCertificateContext(context.Background(), cfg)
}

func prepareClientCertificateContext(ctx context.Context, cfg *Config) (certPEM []byte, privKey *sm2.PrivateKey, err error) {
	certPEM, keyPEM, err := cfg.GetOrGenerateCertificateContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare client certificate: %w", err)
	}
	priv, err := gx509.ReadPrivateKeyFromPem(keyPEM, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("read client private key: %w", err)
	}
	return certPEM, priv, nil
}

// ClientHandshake executes the client-side RFC 8998 TLS 1.3 handshake over rawConn.
func ClientHandshake(rawConn net.Conn, cfg *Config) (*HandshakeResult, error) {
	return ClientHandshakeContext(context.Background(), rawConn, cfg)
}

// ClientHandshakeContext executes the client-side handshake with cancellable local operations.
func ClientHandshakeContext(ctx context.Context, rawConn net.Conn, cfg *Config) (*HandshakeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		cfg = &Config{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("teetls: invalid client config: %w", err)
	}

	// 1. Generate client ephemeral SM2 key pair and random bytes
	clientEphemeralPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("teetls: generate client ephemeral key: %w", err)
	}
	clientEphemeralPubBytes := encodePublicKeySM2(&clientEphemeralPriv.PublicKey)

	var clientRandom [RandomBytesLen]byte
	if _, err := io.ReadFull(rand.Reader, clientRandom[:]); err != nil {
		return nil, fmt.Errorf("teetls: generate client random: %w", err)
	}

	// ClientHello body: clientRandom(32) || clientEphemeralPub(65) || mutualAttestFlag(1)
	clientHelloBody := make([]byte, RandomBytesLen+SM2UncompressedPubKeyLen+1)
	copy(clientHelloBody[:RandomBytesLen], clientRandom[:])
	copy(clientHelloBody[RandomBytesLen:RandomBytesLen+SM2UncompressedPubKeyLen], clientEphemeralPubBytes)
	if cfg.VerifyMutualAttestation {
		clientHelloBody[RandomBytesLen+SM2UncompressedPubKeyLen] = 1
	} else {
		clientHelloBody[RandomBytesLen+SM2UncompressedPubKeyLen] = 0
	}

	// Send ClientHello wrapped in TLSPlaintext record
	clientHelloWire, err := writePlaintextHandshakeMsg(rawConn, HandshakeTypeClientHello, clientHelloBody)
	if err != nil {
		return nil, fmt.Errorf("teetls: send ClientHello: %w", err)
	}

	// Initialize transcript hash accumulator with ClientHello handshake message
	transcript := bytes.NewBuffer(nil)
	transcript.Write(clientHelloWire)

	// 2. Read ServerHello wrapped in TLSPlaintext record
	msgType, serverHelloBody, serverHelloWire, err := readPlaintextHandshakeMsg(rawConn)
	if err != nil {
		return nil, fmt.Errorf("teetls: read ServerHello: %w", err)
	}
	if msgType != HandshakeTypeServerHello {
		return nil, fmt.Errorf("teetls: expected ServerHello (2), got %d", msgType)
	}
	if len(serverHelloBody) < RandomBytesLen+SM2UncompressedPubKeyLen {
		return nil, errors.New("teetls: ServerHello message too short")
	}

	serverRandom := serverHelloBody[:RandomBytesLen]
	serverEphemeralPubBytes := serverHelloBody[RandomBytesLen : RandomBytesLen+SM2UncompressedPubKeyLen]
	serverEphemeralPub, err := decodePublicKeySM2(serverEphemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("teetls: decode server ephemeral public key: %w", err)
	}

	transcript.Write(serverHelloWire)

	// 3. Compute ECDHE shared secret & derive handshake traffic keys
	sharedSecret, err := computeECDHESharedSecret(serverEphemeralPub, clientEphemeralPriv)
	if err != nil {
		return nil, fmt.Errorf("teetls: compute shared secret: %w", err)
	}

	handshakeKeys, err := deriveHandshakeTrafficKeys(sharedSecret, clientRandom[:], serverRandom)
	if err != nil {
		return nil, fmt.Errorf("teetls: derive handshake traffic keys: %w", err)
	}

	// Create handshake record ciphers
	serverHandshakeCipher, err := NewRecordCipher(handshakeKeys.ServerWriteKey, handshakeKeys.ServerWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: server handshake record cipher: %w", err)
	}
	clientHandshakeCipher, err := NewRecordCipher(handshakeKeys.ClientWriteKey, handshakeKeys.ClientWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: client handshake record cipher: %w", err)
	}

	// 4. Read EncryptedExtensions (encrypted)
	hsReader := newEncryptedHandshakeReader(rawConn, serverHandshakeCipher)

	msgType, encExtensionsBody, err := hsReader.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("teetls: read EncryptedExtensions: %w", err)
	}
	if msgType != HandshakeTypeEncryptedExtensions {
		return nil, fmt.Errorf("teetls: expected EncryptedExtensions (8), got %d", msgType)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeEncryptedExtensions, encExtensionsBody))

	mutualRequired := len(encExtensionsBody) > 0 && encExtensionsBody[0] == 1
	if mutualRequired && !cfg.VerifyMutualAttestation && cfg.EvidenceProvider == nil && (len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0) {
		return nil, ErrMutualAttestationRequired
	}

	// 5. Read Certificate (encrypted)
	msgType, certBody, err := hsReader.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("teetls: read server Certificate: %w", err)
	}
	if msgType != HandshakeTypeCertificate {
		return nil, fmt.Errorf("teetls: expected Certificate (11), got %d", msgType)
	}
	serverCertPEM := certBody
	transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificate, certBody))

	// Verify server certificate and attestation evidence
	evidence, err := VerifyPeerCertificateAndEvidence(serverCertPEM, cfg)
	if err != nil {
		return nil, fmt.Errorf("teetls: verify server attestation: %w", err)
	}

	serverGCert, err := gx509.ReadCertificateFromPem(serverCertPEM)
	if err != nil {
		return nil, fmt.Errorf("teetls: parse server certificate: %w", err)
	}
	serverPub, err := extractSM2PublicKey(serverGCert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("teetls: server certificate public key error: %w", err)
	}

	// Snapshot transcript before CertificateVerify
	transcriptForVerify := make([]byte, transcript.Len())
	copy(transcriptForVerify, transcript.Bytes())

	// 6. Read CertificateVerify (encrypted)
	msgType, sigBody, err := hsReader.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("teetls: read CertificateVerify: %w", err)
	}
	if msgType != HandshakeTypeCertificateVerify {
		return nil, fmt.Errorf("teetls: expected CertificateVerify (15), got %d", msgType)
	}

	// Verify server signature directly over transcript (sm2.Verify handles SM3 hashing internally)
	if !serverPub.Verify(transcriptForVerify, sigBody) {
		return nil, errors.New("teetls: server CertificateVerify signature verification failed")
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, sigBody))

	// Snapshot transcript before Server Finished
	transcriptForServerFinished := make([]byte, transcript.Len())
	copy(transcriptForServerFinished, transcript.Bytes())

	// 7. Read Server Finished (encrypted)
	msgType, finishedBody, err := hsReader.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("teetls: read Server Finished: %w", err)
	}
	if msgType != HandshakeTypeFinished {
		return nil, fmt.Errorf("teetls: expected Finished (20), got %d", msgType)
	}

	expectedServerTag := computeHMACSM3(handshakeKeys.ServerFinishedKey, transcriptForServerFinished)
	if !hmac.Equal(finishedBody, expectedServerTag) {
		return nil, errors.New("teetls: server finished HMAC verification failed")
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeFinished, finishedBody))

	if hsReader.HasRemaining() {
		return nil, errors.New("teetls: unexpected trailing handshake data after server Finished")
	}

	// 8. If mutual attestation is negotiated, send Client Certificate & CertificateVerify
	if mutualRequired {
		clientCertPEM, clientPriv, err := prepareClientCertificateContext(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("teetls: prepare client certificate: %w", err)
		}

		// Send client Certificate
		if err := writeEncryptedHandshakeMsg(rawConn, clientHandshakeCipher, HandshakeTypeCertificate, clientCertPEM); err != nil {
			return nil, fmt.Errorf("teetls: send client Certificate: %w", err)
		}
		transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificate, clientCertPEM))

		// Sign transcript before CertificateVerify (sm2.Sign handles SM3 hashing internally)
		clientSig, err := clientPriv.Sign(rand.Reader, transcript.Bytes(), nil)
		if err != nil {
			return nil, fmt.Errorf("teetls: sign client transcript: %w", err)
		}

		if err := writeEncryptedHandshakeMsg(rawConn, clientHandshakeCipher, HandshakeTypeCertificateVerify, clientSig); err != nil {
			return nil, fmt.Errorf("teetls: send client CertificateVerify: %w", err)
		}
		transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, clientSig))
	}

	// 9. Send Client Finished (encrypted)
	clientFinishedTag := computeHMACSM3(handshakeKeys.ClientFinishedKey, transcript.Bytes())
	if err := writeEncryptedHandshakeMsg(rawConn, clientHandshakeCipher, HandshakeTypeFinished, clientFinishedTag); err != nil {
		return nil, fmt.Errorf("teetls: send Client Finished: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeFinished, clientFinishedTag))

	// 10. Handshake complete! Derive application traffic keys bound to the full transcript hash.
	finalTranscriptHash := sm3.Sm3Sum(transcript.Bytes())
	appKeys, err := deriveApplicationTrafficKeys(sharedSecret, finalTranscriptHash[:])
	if err != nil {
		return nil, fmt.Errorf("teetls: derive application traffic keys: %w", err)
	}

	// Instantiate fresh application record ciphers (starting at sequence number 0)
	appServerCipher, err := NewRecordCipher(appKeys.ServerWriteKey, appKeys.ServerWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: create server application cipher: %w", err)
	}
	appClientCipher, err := NewRecordCipher(appKeys.ClientWriteKey, appKeys.ClientWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: create client application cipher: %w", err)
	}

	return &HandshakeResult{
		InCipher:        appServerCipher, // client reads from server
		OutCipher:       appClientCipher, // client writes to server
		PeerCertPEM:     serverCertPEM,
		PeerEvidence:    evidence,
		PeerCertificate: serverGCert,
	}, nil
}

// ServerHandshake executes the server-side RFC 8998 TLS 1.3 handshake over rawConn.
func ServerHandshake(rawConn net.Conn, cfg *Config) (*HandshakeResult, error) {
	return ServerHandshakeContext(context.Background(), rawConn, cfg)
}

// ServerHandshakeContext executes the server-side handshake with cancellable local operations.
func ServerHandshakeContext(ctx context.Context, rawConn net.Conn, cfg *Config) (*HandshakeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		cfg = &Config{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("teetls: invalid server config: %w", err)
	}

	// Prepare server SM2 certificate and private key
	serverCertPEM, serverPriv, err := prepareServerCertificateContext(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("teetls: prepare server certificate: %w", err)
	}

	// 1. Read ClientHello wrapped in TLSPlaintext record
	msgType, clientHelloBody, clientHelloWire, err := readPlaintextHandshakeMsg(rawConn)
	if err != nil {
		return nil, fmt.Errorf("teetls: read ClientHello: %w", err)
	}
	if msgType != HandshakeTypeClientHello {
		return nil, fmt.Errorf("teetls: expected ClientHello (1), got %d", msgType)
	}
	if len(clientHelloBody) < RandomBytesLen+SM2UncompressedPubKeyLen {
		return nil, errors.New("teetls: ClientHello message too short")
	}

	clientRandom := clientHelloBody[:RandomBytesLen]
	clientEphemeralPubBytes := clientHelloBody[RandomBytesLen : RandomBytesLen+SM2UncompressedPubKeyLen]
	clientEphemeralPub, err := decodePublicKeySM2(clientEphemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("teetls: decode client ephemeral public key: %w", err)
	}

	var clientRequestedMutual bool
	if len(clientHelloBody) > RandomBytesLen+SM2UncompressedPubKeyLen && clientHelloBody[RandomBytesLen+SM2UncompressedPubKeyLen] == 1 {
		clientRequestedMutual = true
	}

	transcript := bytes.NewBuffer(nil)
	transcript.Write(clientHelloWire)

	// 2. Generate server ephemeral SM2 key pair and random bytes
	serverEphemeralPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("teetls: generate server ephemeral key: %w", err)
	}
	serverEphemeralPubBytes := encodePublicKeySM2(&serverEphemeralPriv.PublicKey)

	var serverRandom [RandomBytesLen]byte
	if _, err := io.ReadFull(rand.Reader, serverRandom[:]); err != nil {
		return nil, fmt.Errorf("teetls: generate server random: %w", err)
	}

	// ServerHello body: serverRandom(32) || serverEphemeralPub(65)
	serverHelloBody := make([]byte, RandomBytesLen+SM2UncompressedPubKeyLen)
	copy(serverHelloBody[:RandomBytesLen], serverRandom[:])
	copy(serverHelloBody[RandomBytesLen:], serverEphemeralPubBytes)

	// Send ServerHello wrapped in TLSPlaintext record
	serverHelloWire, err := writePlaintextHandshakeMsg(rawConn, HandshakeTypeServerHello, serverHelloBody)
	if err != nil {
		return nil, fmt.Errorf("teetls: send ServerHello: %w", err)
	}
	transcript.Write(serverHelloWire)

	// 3. Compute ECDHE shared secret & derive handshake traffic keys
	sharedSecret, err := computeECDHESharedSecret(clientEphemeralPub, serverEphemeralPriv)
	if err != nil {
		return nil, fmt.Errorf("teetls: compute shared secret: %w", err)
	}

	handshakeKeys, err := deriveHandshakeTrafficKeys(sharedSecret, clientRandom, serverRandom[:])
	if err != nil {
		return nil, fmt.Errorf("teetls: derive handshake traffic keys: %w", err)
	}

	serverHandshakeCipher, err := NewRecordCipher(handshakeKeys.ServerWriteKey, handshakeKeys.ServerWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: server handshake record cipher: %w", err)
	}
	clientHandshakeCipher, err := NewRecordCipher(handshakeKeys.ClientWriteKey, handshakeKeys.ClientWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: client handshake record cipher: %w", err)
	}

	// 4. Send EncryptedExtensions (encrypted)
	var encExtBody []byte
	if cfg.VerifyMutualAttestation || clientRequestedMutual {
		encExtBody = []byte{1} // indicates mutual attestation expected
	} else {
		encExtBody = []byte{0}
	}
	if err := writeEncryptedHandshakeMsg(rawConn, serverHandshakeCipher, HandshakeTypeEncryptedExtensions, encExtBody); err != nil {
		return nil, fmt.Errorf("teetls: send EncryptedExtensions: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeEncryptedExtensions, encExtBody))

	// 5. Send server Certificate (encrypted)
	if err := writeEncryptedHandshakeMsg(rawConn, serverHandshakeCipher, HandshakeTypeCertificate, serverCertPEM); err != nil {
		return nil, fmt.Errorf("teetls: send server Certificate: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificate, serverCertPEM))

	// 6. Send CertificateVerify (encrypted)
	// SM2 sign transcript directly using server private key (sm2.Sign handles SM3 hashing internally)
	serverSig, err := serverPriv.Sign(rand.Reader, transcript.Bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("teetls: sign server transcript: %w", err)
	}
	if err := writeEncryptedHandshakeMsg(rawConn, serverHandshakeCipher, HandshakeTypeCertificateVerify, serverSig); err != nil {
		return nil, fmt.Errorf("teetls: send server CertificateVerify: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, serverSig))

	// 7. Send Server Finished (encrypted)
	serverFinishedTag := computeHMACSM3(handshakeKeys.ServerFinishedKey, transcript.Bytes())
	if err := writeEncryptedHandshakeMsg(rawConn, serverHandshakeCipher, HandshakeTypeFinished, serverFinishedTag); err != nil {
		return nil, fmt.Errorf("teetls: send Server Finished: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeFinished, serverFinishedTag))

	var peerCertPEM []byte
	var peerEvidence *CSVEvidenceExtension
	var peerGCert *gx509.Certificate

	hsReader := newEncryptedHandshakeReader(rawConn, clientHandshakeCipher)

	// 8. If mutual attestation is required/performed, read Client Certificate & CertificateVerify
	if cfg.VerifyMutualAttestation || clientRequestedMutual {
		// Read client Certificate
		msgType, clientCertBody, err := hsReader.ReadMsg()
		if err != nil {
			return nil, fmt.Errorf("teetls: read client Certificate: %w", err)
		}
		if msgType != HandshakeTypeCertificate {
			return nil, fmt.Errorf("teetls: expected client Certificate (11), got %d", msgType)
		}
		peerCertPEM = clientCertBody
		transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificate, clientCertBody))

		// Verify client certificate & attestation evidence
		evidence, err := VerifyPeerCertificateAndEvidence(peerCertPEM, cfg)
		if err != nil {
			return nil, fmt.Errorf("teetls: verify client attestation: %w", err)
		}
		peerEvidence = evidence

		clientGCert, err := gx509.ReadCertificateFromPem(peerCertPEM)
		if err != nil {
			return nil, fmt.Errorf("teetls: parse client certificate: %w", err)
		}
		peerGCert = clientGCert

		clientPub, err := extractSM2PublicKey(clientGCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("teetls: client certificate public key error: %w", err)
		}

		// Snapshot transcript before client CertificateVerify
		clientTranscriptForVerify := make([]byte, transcript.Len())
		copy(clientTranscriptForVerify, transcript.Bytes())

		// Read client CertificateVerify
		msgType, clientSigBody, err := hsReader.ReadMsg()
		if err != nil {
			return nil, fmt.Errorf("teetls: read client CertificateVerify: %w", err)
		}
		if msgType != HandshakeTypeCertificateVerify {
			return nil, fmt.Errorf("teetls: expected client CertificateVerify (15), got %d", msgType)
		}

		// Verify client signature directly over transcript
		if !clientPub.Verify(clientTranscriptForVerify, clientSigBody) {
			return nil, errors.New("teetls: client CertificateVerify signature verification failed")
		}
		transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, clientSigBody))
	}

	// 9. Read Client Finished (encrypted)
	expectedClientTag := computeHMACSM3(handshakeKeys.ClientFinishedKey, transcript.Bytes())

	msgType, clientFinishedBody, err := hsReader.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("teetls: read Client Finished: %w", err)
	}
	if msgType != HandshakeTypeFinished {
		return nil, fmt.Errorf("teetls: expected Finished (20), got %d", msgType)
	}

	if !hmac.Equal(clientFinishedBody, expectedClientTag) {
		return nil, errors.New("teetls: client finished HMAC verification failed")
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeFinished, clientFinishedBody))

	if hsReader.HasRemaining() {
		return nil, errors.New("teetls: unexpected trailing handshake data after client Finished")
	}

	// 10. Handshake complete! Derive application traffic keys bound to the full transcript hash.
	finalTranscriptHash := sm3.Sm3Sum(transcript.Bytes())
	appKeys, err := deriveApplicationTrafficKeys(sharedSecret, finalTranscriptHash[:])
	if err != nil {
		return nil, fmt.Errorf("teetls: derive application traffic keys: %w", err)
	}

	// Instantiate fresh application record ciphers (starting at sequence number 0)
	appClientCipher, err := NewRecordCipher(appKeys.ClientWriteKey, appKeys.ClientWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: create client application cipher: %w", err)
	}
	appServerCipher, err := NewRecordCipher(appKeys.ServerWriteKey, appKeys.ServerWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: create server application cipher: %w", err)
	}

	return &HandshakeResult{
		InCipher:        appClientCipher, // server reads from client
		OutCipher:       appServerCipher, // server writes to client
		PeerCertPEM:     peerCertPEM,
		PeerEvidence:    peerEvidence,
		PeerCertificate: peerGCert,
	}, nil
}

// encryptedHandshakeReader buffers decrypted plaintext from TLSCiphertext records
// and parses discrete handshake messages, supporting record coalescing and fragmentation.
type encryptedHandshakeReader struct {
	r      io.Reader
	cipher *RecordCipher
	buf    []byte
}

func newEncryptedHandshakeReader(r io.Reader, cipher *RecordCipher) *encryptedHandshakeReader {
	return &encryptedHandshakeReader{
		r:      r,
		cipher: cipher,
	}
}

// ReadMsg reads the next discrete handshake message. It unseals subsequent TLSCiphertext
// records until at least one complete handshake message is buffered.
func (hr *encryptedHandshakeReader) ReadMsg() (uint8, []byte, error) {
	for {
		if len(hr.buf) >= HandshakeHeaderLen {
			msgLen := int(hr.buf[1])<<16 | int(hr.buf[2])<<8 | int(hr.buf[3])
			if msgLen < 0 || msgLen > 1<<24 {
				return 0, nil, errors.New("teetls: invalid handshake message length")
			}
			totalLen := HandshakeHeaderLen + msgLen
			if totalLen > maxHandshakeBufferSize {
				return 0, nil, errors.New("teetls: handshake message exceeds buffer limit")
			}
			if len(hr.buf) >= totalLen {
				msgType := hr.buf[0]
				body := make([]byte, msgLen)
				copy(body, hr.buf[HandshakeHeaderLen:totalLen])
				hr.buf = hr.buf[totalLen:]
				return msgType, body, nil
			}
		}

		header := make([]byte, RecordHeaderLen)
		if _, err := io.ReadFull(hr.r, header); err != nil {
			return 0, nil, fmt.Errorf("read record header: %w", err)
		}

		if header[0] != byte(RecordTypeApplicationData) {
			return 0, nil, ErrInvalidRecordHeader
		}
		payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
		if payloadLen <= 0 || payloadLen > MaxCiphertextLength {
			return 0, nil, ErrCiphertextTooLarge
		}

		fullRecord := make([]byte, RecordHeaderLen+payloadLen)
		copy(fullRecord[:RecordHeaderLen], header)
		if _, err := io.ReadFull(hr.r, fullRecord[RecordHeaderLen:]); err != nil {
			return 0, nil, fmt.Errorf("read record payload: %w", err)
		}

		recType, plaintext, err := hr.cipher.Unseal(fullRecord)
		if err != nil {
			return 0, nil, fmt.Errorf("unseal record: %w", err)
		}
		if recType != RecordTypeHandshake {
			return 0, nil, fmt.Errorf("teetls: expected handshake record type (22), got %d", recType)
		}

		if len(hr.buf)+len(plaintext) > maxHandshakeBufferSize {
			return 0, nil, errors.New("teetls: handshake message buffer limit exceeded")
		}

		hr.buf = append(hr.buf, plaintext...)
	}
}

// HasRemaining returns true if unparsed handshake plaintext remains in the reader's buffer.
func (hr *encryptedHandshakeReader) HasRemaining() bool {
	return len(hr.buf) > 0
}

// readEncryptedHandshakeMsg reads one complete handshake message from r using cipher.
// Maintained for testing and compatibility.
func readEncryptedHandshakeMsg(r io.Reader, cipher *RecordCipher) (uint8, []byte, error) {
	reader := newEncryptedHandshakeReader(r, cipher)
	return reader.ReadMsg()
}

// writeEncryptedHandshakeMsg seals a handshake message into RecordTypeHandshake record(s) and writes it to w.
func writeEncryptedHandshakeMsg(w io.Writer, cipher *RecordCipher, msgType uint8, body []byte) error {
	hsMsg := encodeHandshakeMsg(msgType, body)
	for len(hsMsg) > 0 {
		chunkSize := len(hsMsg)
		if chunkSize > MaxPlaintextLength {
			chunkSize = MaxPlaintextLength
		}
		record, err := cipher.Seal(RecordTypeHandshake, hsMsg[:chunkSize])
		if err != nil {
			return fmt.Errorf("seal handshake record: %w", err)
		}
		if _, err := w.Write(record); err != nil {
			return fmt.Errorf("write record: %w", err)
		}
		hsMsg = hsMsg[chunkSize:]
	}
	return nil
}
