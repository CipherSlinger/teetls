package teetls

import (
	"bytes"
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

// HandshakeKeys holds the symmetric keys and IVs derived via HKDF-SM3.
type HandshakeKeys struct {
	ClientWriteKey    []byte // 16 bytes
	ClientWriteIV     []byte // 12 bytes
	ServerWriteKey    []byte // 16 bytes
	ServerWriteIV     []byte // 12 bytes
	ServerFinishedKey []byte // 32 bytes
	ClientFinishedKey []byte // 32 bytes
}

// HandshakeResult holds peer attestation and certificate after a successful handshake.
type HandshakeResult struct {
	InCipher        *RecordCipher
	OutCipher       *RecordCipher
	PeerCertPEM     []byte
	PeerEvidence    *CSVEvidenceExtension
	PeerCertificate *gx509.Certificate
}

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

// readHandshakeMsg reads exactly one handshake message from an io.Reader.
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

// deriveKeys computes the RFC 8998 ShangMi TLS 1.3 symmetric keys using HKDF-SM3.
func deriveKeys(sharedSecret, clientRandom, serverRandom []byte) (*HandshakeKeys, error) {
	salt := append(append([]byte{}, clientRandom...), serverRandom...)
	info := []byte("tls13-rfc8998-sm4-gcm-sm3")
	kdf := hkdf.New(sm3.New, sharedSecret, salt, info)

	keys := &HandshakeKeys{
		ClientWriteKey:    make([]byte, 16),
		ClientWriteIV:     make([]byte, 12),
		ServerWriteKey:    make([]byte, 16),
		ServerWriteIV:     make([]byte, 12),
		ServerFinishedKey: make([]byte, 32),
		ClientFinishedKey: make([]byte, 32),
	}

	if _, err := io.ReadFull(kdf, keys.ClientWriteKey); err != nil {
		return nil, fmt.Errorf("derive client write key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ClientWriteIV); err != nil {
		return nil, fmt.Errorf("derive client write iv: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerWriteKey); err != nil {
		return nil, fmt.Errorf("derive server write key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerWriteIV); err != nil {
		return nil, fmt.Errorf("derive server write iv: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerFinishedKey); err != nil {
		return nil, fmt.Errorf("derive server finished key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ClientFinishedKey); err != nil {
		return nil, fmt.Errorf("derive client finished key: %w", err)
	}

	return keys, nil
}

// computeHMACSM3 calculates HMAC-SM3 over the input data using the given key.
func computeHMACSM3(key, data []byte) []byte {
	mac := hmac.New(sm3.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// prepareServerCertificate resolves or generates server SM2 certificate and private key.
func prepareServerCertificate(cfg *Config) (certPEM []byte, privKey *sm2.PrivateKey, err error) {
	if len(cfg.CertPEM) > 0 && len(cfg.KeyPEM) > 0 {
		priv, err := gx509.ReadPrivateKeyFromPem(cfg.KeyPEM, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("read server private key: %w", err)
		}
		return cfg.CertPEM, priv, nil
	}

	if cfg.EvidenceProvider == nil {
		return nil, nil, errors.New("teetls: server requires either CertPEM/KeyPEM or EvidenceProvider")
	}

	certPEM, keyPEM, err := GenerateSM2CertificateWithEvidence(cfg.EvidenceProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server certificate: %w", err)
	}
	priv, err := gx509.ReadPrivateKeyFromPem(keyPEM, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("read generated server private key: %w", err)
	}
	return certPEM, priv, nil
}

// prepareClientCertificate resolves or generates client SM2 certificate and private key for mutual attestation.
func prepareClientCertificate(cfg *Config) (certPEM []byte, privKey *sm2.PrivateKey, err error) {
	if len(cfg.CertPEM) > 0 && len(cfg.KeyPEM) > 0 {
		priv, err := gx509.ReadPrivateKeyFromPem(cfg.KeyPEM, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("read client private key: %w", err)
		}
		return cfg.CertPEM, priv, nil
	}

	if cfg.EvidenceProvider == nil {
		return nil, nil, errors.New("teetls: mutual attestation enabled on client but no EvidenceProvider provided")
	}

	certPEM, keyPEM, err := GenerateSM2CertificateWithEvidence(cfg.EvidenceProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client certificate: %w", err)
	}
	priv, err := gx509.ReadPrivateKeyFromPem(keyPEM, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("read generated client private key: %w", err)
	}
	return certPEM, priv, nil
}

// ClientHandshake executes the client-side RFC 8998 TLS 1.3 handshake over rawConn.
func ClientHandshake(rawConn net.Conn, cfg *Config) (*HandshakeResult, error) {
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

	clientHelloWire := encodeHandshakeMsg(HandshakeTypeClientHello, clientHelloBody)

	// Initialize transcript hash accumulator
	transcript := bytes.NewBuffer(nil)
	transcript.Write(clientHelloWire)

	// Send ClientHello
	if _, err := rawConn.Write(clientHelloWire); err != nil {
		return nil, fmt.Errorf("teetls: send ClientHello: %w", err)
	}

	// 2. Read ServerHello
	msgType, serverHelloBody, err := readHandshakeMsg(rawConn)
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

	transcript.Write(encodeHandshakeMsg(HandshakeTypeServerHello, serverHelloBody))

	// 3. Compute ECDHE shared secret & derive handshake keys
	sharedSecret, err := computeECDHESharedSecret(serverEphemeralPub, clientEphemeralPriv)
	if err != nil {
		return nil, fmt.Errorf("teetls: compute shared secret: %w", err)
	}

	keys, err := deriveKeys(sharedSecret, clientRandom[:], serverRandom)
	if err != nil {
		return nil, fmt.Errorf("teetls: derive keys: %w", err)
	}

	// Create handshake record ciphers
	// Server to client cipher
	serverCipher, err := NewRecordCipher(keys.ServerWriteKey, keys.ServerWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: server record cipher: %w", err)
	}
	// Client to server cipher
	clientCipher, err := NewRecordCipher(keys.ClientWriteKey, keys.ClientWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: client record cipher: %w", err)
	}

	// 4. Read EncryptedExtensions (encrypted)
	msgType, encExtensionsBody, err := readEncryptedHandshakeMsg(rawConn, serverCipher)
	if err != nil {
		return nil, fmt.Errorf("teetls: read EncryptedExtensions: %w", err)
	}
	if msgType != HandshakeTypeEncryptedExtensions {
		return nil, fmt.Errorf("teetls: expected EncryptedExtensions (8), got %d", msgType)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeEncryptedExtensions, encExtensionsBody))

	// 5. Read Certificate (encrypted)
	msgType, certBody, err := readEncryptedHandshakeMsg(rawConn, serverCipher)
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
	msgType, sigBody, err := readEncryptedHandshakeMsg(rawConn, serverCipher)
	if err != nil {
		return nil, fmt.Errorf("teetls: read CertificateVerify: %w", err)
	}
	if msgType != HandshakeTypeCertificateVerify {
		return nil, fmt.Errorf("teetls: expected CertificateVerify (15), got %d", msgType)
	}

	// Verify server signature over transcript hash
	transcriptSM3 := sm3.Sm3Sum(transcriptForVerify)
	if !serverPub.Verify(transcriptSM3, sigBody) {
		return nil, errors.New("teetls: server CertificateVerify signature verification failed")
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, sigBody))

	// Snapshot transcript before Server Finished
	transcriptForServerFinished := make([]byte, transcript.Len())
	copy(transcriptForServerFinished, transcript.Bytes())

	// 7. Read Server Finished (encrypted)
	msgType, finishedBody, err := readEncryptedHandshakeMsg(rawConn, serverCipher)
	if err != nil {
		return nil, fmt.Errorf("teetls: read Server Finished: %w", err)
	}
	if msgType != HandshakeTypeFinished {
		return nil, fmt.Errorf("teetls: expected Finished (20), got %d", msgType)
	}

	expectedServerTag := computeHMACSM3(keys.ServerFinishedKey, transcriptForServerFinished)
	if !hmac.Equal(finishedBody, expectedServerTag) {
		return nil, errors.New("teetls: server finished HMAC verification failed")
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeFinished, finishedBody))

	// 8. If mutual attestation is requested, send Client Certificate & CertificateVerify
	if cfg.VerifyMutualAttestation {
		clientCertPEM, clientPriv, err := prepareClientCertificate(cfg)
		if err != nil {
			return nil, fmt.Errorf("teetls: prepare client certificate: %w", err)
		}

		// Send client Certificate
		if err := writeEncryptedHandshakeMsg(rawConn, clientCipher, HandshakeTypeCertificate, clientCertPEM); err != nil {
			return nil, fmt.Errorf("teetls: send client Certificate: %w", err)
		}
		transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificate, clientCertPEM))

		// Sign transcript before CertificateVerify
		clientTranscriptSM3 := sm3.Sm3Sum(transcript.Bytes())
		clientSig, err := clientPriv.Sign(rand.Reader, clientTranscriptSM3, nil)
		if err != nil {
			return nil, fmt.Errorf("teetls: sign client transcript: %w", err)
		}

		if err := writeEncryptedHandshakeMsg(rawConn, clientCipher, HandshakeTypeCertificateVerify, clientSig); err != nil {
			return nil, fmt.Errorf("teetls: send client CertificateVerify: %w", err)
		}
		transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, clientSig))
	}

	// 9. Send Client Finished (encrypted)
	clientFinishedTag := computeHMACSM3(keys.ClientFinishedKey, transcript.Bytes())
	if err := writeEncryptedHandshakeMsg(rawConn, clientCipher, HandshakeTypeFinished, clientFinishedTag); err != nil {
		return nil, fmt.Errorf("teetls: send Client Finished: %w", err)
	}

	// Handshake complete! Reset sequence numbers on ciphers for application data traffic.
	clientCipher.Reset()
	serverCipher.Reset()

	return &HandshakeResult{
		InCipher:        serverCipher, // client reads from server
		OutCipher:       clientCipher, // client writes to server
		PeerCertPEM:     serverCertPEM,
		PeerEvidence:    evidence,
		PeerCertificate: serverGCert,
	}, nil
}

// ServerHandshake executes the server-side RFC 8998 TLS 1.3 handshake over rawConn.
func ServerHandshake(rawConn net.Conn, cfg *Config) (*HandshakeResult, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("teetls: invalid server config: %w", err)
	}

	// Prepare server SM2 certificate and private key
	serverCertPEM, serverPriv, err := prepareServerCertificate(cfg)
	if err != nil {
		return nil, fmt.Errorf("teetls: prepare server certificate: %w", err)
	}

	// 1. Read ClientHello
	msgType, clientHelloBody, err := readHandshakeMsg(rawConn)
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
	transcript.Write(encodeHandshakeMsg(HandshakeTypeClientHello, clientHelloBody))

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

	serverHelloWire := encodeHandshakeMsg(HandshakeTypeServerHello, serverHelloBody)
	transcript.Write(serverHelloWire)

	// Send ServerHello
	if _, err := rawConn.Write(serverHelloWire); err != nil {
		return nil, fmt.Errorf("teetls: send ServerHello: %w", err)
	}

	// 3. Compute ECDHE shared secret & derive keys
	sharedSecret, err := computeECDHESharedSecret(clientEphemeralPub, serverEphemeralPriv)
	if err != nil {
		return nil, fmt.Errorf("teetls: compute shared secret: %w", err)
	}

	keys, err := deriveKeys(sharedSecret, clientRandom, serverRandom[:])
	if err != nil {
		return nil, fmt.Errorf("teetls: derive keys: %w", err)
	}

	serverCipher, err := NewRecordCipher(keys.ServerWriteKey, keys.ServerWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: server record cipher: %w", err)
	}
	clientCipher, err := NewRecordCipher(keys.ClientWriteKey, keys.ClientWriteIV)
	if err != nil {
		return nil, fmt.Errorf("teetls: client record cipher: %w", err)
	}

	// 4. Send EncryptedExtensions (encrypted)
	var encExtBody []byte
	if cfg.VerifyMutualAttestation || clientRequestedMutual {
		encExtBody = []byte{1} // indicates mutual attestation expected
	} else {
		encExtBody = []byte{0}
	}
	if err := writeEncryptedHandshakeMsg(rawConn, serverCipher, HandshakeTypeEncryptedExtensions, encExtBody); err != nil {
		return nil, fmt.Errorf("teetls: send EncryptedExtensions: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeEncryptedExtensions, encExtBody))

	// 5. Send server Certificate (encrypted)
	if err := writeEncryptedHandshakeMsg(rawConn, serverCipher, HandshakeTypeCertificate, serverCertPEM); err != nil {
		return nil, fmt.Errorf("teetls: send server Certificate: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificate, serverCertPEM))

	// 6. Send CertificateVerify (encrypted)
	// SM2 sign transcript SM3 digest using server private key
	transcriptSM3 := sm3.Sm3Sum(transcript.Bytes())
	serverSig, err := serverPriv.Sign(rand.Reader, transcriptSM3, nil)
	if err != nil {
		return nil, fmt.Errorf("teetls: sign server transcript: %w", err)
	}
	if err := writeEncryptedHandshakeMsg(rawConn, serverCipher, HandshakeTypeCertificateVerify, serverSig); err != nil {
		return nil, fmt.Errorf("teetls: send server CertificateVerify: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, serverSig))

	// 7. Send Server Finished (encrypted)
	serverFinishedTag := computeHMACSM3(keys.ServerFinishedKey, transcript.Bytes())
	if err := writeEncryptedHandshakeMsg(rawConn, serverCipher, HandshakeTypeFinished, serverFinishedTag); err != nil {
		return nil, fmt.Errorf("teetls: send Server Finished: %w", err)
	}
	transcript.Write(encodeHandshakeMsg(HandshakeTypeFinished, serverFinishedTag))

	var peerCertPEM []byte
	var peerEvidence *CSVEvidenceExtension
	var peerGCert *gx509.Certificate

	// 8. If mutual attestation is required/performed, read Client Certificate & CertificateVerify
	if cfg.VerifyMutualAttestation || clientRequestedMutual {
		// Read client Certificate
		msgType, clientCertBody, err := readEncryptedHandshakeMsg(rawConn, clientCipher)
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
		msgType, clientSigBody, err := readEncryptedHandshakeMsg(rawConn, clientCipher)
		if err != nil {
			return nil, fmt.Errorf("teetls: read client CertificateVerify: %w", err)
		}
		if msgType != HandshakeTypeCertificateVerify {
			return nil, fmt.Errorf("teetls: expected client CertificateVerify (15), got %d", msgType)
		}

		clientTranscriptSM3 := sm3.Sm3Sum(clientTranscriptForVerify)
		if !clientPub.Verify(clientTranscriptSM3, clientSigBody) {
			return nil, errors.New("teetls: client CertificateVerify signature verification failed")
		}
		transcript.Write(encodeHandshakeMsg(HandshakeTypeCertificateVerify, clientSigBody))
	}

	// 9. Read Client Finished (encrypted)
	expectedClientTag := computeHMACSM3(keys.ClientFinishedKey, transcript.Bytes())

	msgType, clientFinishedBody, err := readEncryptedHandshakeMsg(rawConn, clientCipher)
	if err != nil {
		return nil, fmt.Errorf("teetls: read Client Finished: %w", err)
	}
	if msgType != HandshakeTypeFinished {
		return nil, fmt.Errorf("teetls: expected Finished (20), got %d", msgType)
	}

	if !hmac.Equal(clientFinishedBody, expectedClientTag) {
		return nil, errors.New("teetls: client finished HMAC verification failed")
	}

	// Handshake complete! Reset sequence numbers on ciphers for application data traffic.
	clientCipher.Reset()
	serverCipher.Reset()

	return &HandshakeResult{
		InCipher:        clientCipher, // server reads from client
		OutCipher:       serverCipher, // server writes to client
		PeerCertPEM:     peerCertPEM,
		PeerEvidence:    peerEvidence,
		PeerCertificate: peerGCert,
	}, nil
}

// readEncryptedHandshakeMsg reads a TLS record containing an encrypted handshake message.
func readEncryptedHandshakeMsg(r io.Reader, cipher *RecordCipher) (uint8, []byte, error) {
	// Read 5-byte record header first to know record length
	header := make([]byte, RecordHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
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
	if _, err := io.ReadFull(r, fullRecord[RecordHeaderLen:]); err != nil {
		return 0, nil, fmt.Errorf("read record payload: %w", err)
	}

	recType, plaintext, err := cipher.Unseal(fullRecord)
	if err != nil {
		return 0, nil, fmt.Errorf("unseal record: %w", err)
	}
	if recType != RecordTypeHandshake {
		return 0, nil, fmt.Errorf("teetls: expected handshake record type (22), got %d", recType)
	}

	// Parse handshake header: 1 byte type + 3 bytes length
	if len(plaintext) < HandshakeHeaderLen {
		return 0, nil, errors.New("teetls: decrypted handshake fragment too short")
	}
	msgType := plaintext[0]
	msgLen := int(plaintext[1])<<16 | int(plaintext[2])<<8 | int(plaintext[3])
	if msgLen != len(plaintext)-HandshakeHeaderLen {
		return 0, nil, errors.New("teetls: handshake message length mismatch in record")
	}

	return msgType, plaintext[HandshakeHeaderLen:], nil
}

// writeEncryptedHandshakeMsg seals a handshake message into a RecordTypeHandshake record and writes it to w.
func writeEncryptedHandshakeMsg(w io.Writer, cipher *RecordCipher, msgType uint8, body []byte) error {
	hsMsg := encodeHandshakeMsg(msgType, body)
	record, err := cipher.Seal(RecordTypeHandshake, hsMsg)
	if err != nil {
		return fmt.Errorf("seal handshake record: %w", err)
	}
	if _, err := w.Write(record); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	return nil
}
