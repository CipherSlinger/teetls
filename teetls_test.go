package teetls

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	gx509 "github.com/tjfoc/gmsm/x509"
)

// TestTEETLS_HandshakeAndDataTransfer tests TCP Listen + Dial, send secret message,
// echo back ACK, and verify plaintext data transfer.
func TestTEETLS_HandshakeAndDataTransfer(t *testing.T) {
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

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverErrCh <- err
			return
		}
		_, err = conn.Write(append([]byte("ACK: "), buf[:n]...))
		serverErrCh <- err
	}()

	clientConn, err := Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	// Check PeerEvidence and PeerCertificate on client
	if clientConn.PeerEvidence() == nil {
		t.Errorf("expected non-nil PeerEvidence on client conn")
	}
	if clientConn.PeerCertificate() == nil {
		t.Errorf("expected non-nil PeerCertificate on client conn")
	}

	msg := []byte("Secret confidential payload over TEE-TLS 1.3")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := clientConn.Read(reply)
	if err != nil && err != io.EOF {
		t.Fatalf("client read failed: %v", err)
	}
	expected := "ACK: Secret confidential payload over TEE-TLS 1.3"
	if string(reply[:n]) != expected {
		t.Fatalf("unexpected reply: %s", string(reply[:n]))
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// TestTEETLS_AntiMITMPublicKeyTampering verifies that handshake fails if peer certificate
// public key doesn't match report USER_DATA.
func TestTEETLS_AntiMITMPublicKeyTampering(t *testing.T) {
	mockProv := NewMockEvidenceProvider()

	// Generate legitimate cert & key
	certPEM, keyPEM, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}

	// Tamper: Generate a DIFFERENT SM2 key pair and create a new cert with the same evidence extension
	tamperedPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate tampered key: %v", err)
	}

	parsedCert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	var evExt *pkix.Extension
	for i := range parsedCert.Extensions {
		if parsedCert.Extensions[i].Id.Equal(OIDCSVEvidence) {
			evExt = &parsedCert.Extensions[i]
			break
		}
	}
	if evExt == nil {
		t.Fatal("evidence extension not found")
	}

	// Create tampered certificate with new key but old evidence
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	tamperedTemplate := &gx509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Tampered Certificate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []gx509.ExtKeyUsage{gx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       []pkix.Extension{*evExt},
	}

	tamperedCertPEM, err := gx509.CreateCertificateToPem(tamperedTemplate, tamperedTemplate, &tamperedPriv.PublicKey, tamperedPriv)
	if err != nil {
		t.Fatalf("create tampered cert: %v", err)
	}
	tamperedKeyPEM, err := gx509.WritePrivateKeyToPem(tamperedPriv, nil)
	if err != nil {
		t.Fatalf("marshal tampered key: %v", err)
	}

	_ = keyPEM

	serverCfg := &Config{
		Mode:    ModeStrict,
		CertPEM: tamperedCertPEM,
		KeyPEM:  tamperedKeyPEM,
	}

	clientCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
		ExpectedMeasurements: []string{
			mockProv.GetMeasurementHex(),
		},
	}

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Read(make([]byte, 10))
			conn.Close()
		}
	}()

	_, err = Dial("tcp", listener.Addr().String(), clientCfg)
	if err == nil {
		t.Fatal("expected handshake failure due to public key binding mismatch, got nil error")
	}

	if !strings.Contains(err.Error(), "does not match attestation report USER_DATA") {
		t.Fatalf("expected USER_DATA mismatch error, got: %v", err)
	}
}

// TestTEETLS_MeasurementPolicyStrictVsPermissive tests measurement policy:
// Mismatch fails in strict mode, succeeds with warning in permissive mode.
func TestTEETLS_MeasurementPolicyStrictVsPermissive(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	wrongMeasurement := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// 1. Strict Mode -> should fail
	serverCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
	}
	strictClientCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
		ExpectedMeasurements: []string{
			wrongMeasurement,
		},
	}

	listener1, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener1.Close()

	go func() {
		conn, err := listener1.Accept()
		if err == nil {
			conn.Read(make([]byte, 10))
			conn.Close()
		}
	}()

	_, err = Dial("tcp", listener1.Addr().String(), strictClientCfg)
	if err == nil {
		t.Fatal("expected error in strict mode with wrong measurement, got nil")
	}
	if !strings.Contains(err.Error(), "measurement hash does not match") {
		t.Fatalf("expected measurement mismatch error, got: %v", err)
	}

	// 2. Permissive Mode -> should succeed
	permissiveClientCfg := &Config{
		Mode:             ModePermissive,
		EvidenceProvider: mockProv,
		ExpectedMeasurements: []string{
			wrongMeasurement,
		},
	}

	listener2, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener2.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		conn.Write(append([]byte("PERMISSIVE-"), buf[:n]...))
	}()

	pConn, err := Dial("tcp", listener2.Addr().String(), permissiveClientCfg)
	if err != nil {
		t.Fatalf("expected success in permissive mode, got error: %v", err)
	}
	defer pConn.Close()

	if _, err := pConn.Write([]byte("HELLO")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp := make([]byte, 64)
	n, err := pConn.Read(resp)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(resp[:n]) != "PERMISSIVE-HELLO" {
		t.Fatalf("unexpected response: %s", string(resp[:n]))
	}

	<-serverDone
}

// TestTEETLS_MutualAttestation tests client and server both presenting and verifying CSV evidence.
func TestTEETLS_MutualAttestation(t *testing.T) {
	mockProv := NewMockEvidenceProvider()

	serverCfg := &Config{
		Mode:                    ModeStrict,
		EvidenceProvider:        mockProv,
		VerifyMutualAttestation: true,
		ExpectedMeasurements: []string{
			mockProv.GetMeasurementHex(),
		},
	}

	clientCfg := &Config{
		Mode:                    ModeStrict,
		EvidenceProvider:        mockProv,
		VerifyMutualAttestation: true,
		ExpectedMeasurements: []string{
			mockProv.GetMeasurementHex(),
		},
	}

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		sConn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer sConn.Close()

		tConn, ok := sConn.(*Conn)
		if !ok {
			serverErrCh <- errors.New("expected *Conn")
			return
		}

		if err := tConn.Handshake(); err != nil {
			serverErrCh <- fmt.Errorf("server handshake: %w", err)
			return
		}

		if tConn.PeerEvidence() == nil {
			serverErrCh <- errors.New("server expected non-nil client PeerEvidence")
			return
		}
		if tConn.PeerCertificate() == nil {
			serverErrCh <- errors.New("server expected non-nil client PeerCertificate")
			return
		}

		buf := make([]byte, 128)
		n, err := tConn.Read(buf)
		if err != nil {
			serverErrCh <- err
			return
		}
		_, err = tConn.Write(append([]byte("MUTUAL-OK: "), buf[:n]...))
		serverErrCh <- err
	}()

	cConn, err := Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer cConn.Close()

	if cConn.PeerEvidence() == nil {
		t.Fatal("client expected non-nil server PeerEvidence")
	}

	if _, err := cConn.Write([]byte("ping mutual")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	reply := make([]byte, 128)
	n, err := cConn.Read(reply)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(reply[:n]) != "MUTUAL-OK: ping mutual" {
		t.Fatalf("unexpected reply: %s", string(reply[:n]))
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// TestTEETLS_HTTPTransport tests running standard http.Server on Listen(...) and
// using NewHTTPClient(...) to send GET/POST requests and verify responses.
func TestTEETLS_HTTPTransport(t *testing.T) {
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
		Timeout: 5 * time.Second,
	}

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello from TEE-TLS HTTP Server!"))
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			w.Write(append([]byte("ECHO: "), body...))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	server := &http.Server{
		Handler: mux,
	}
	go server.Serve(listener)
	defer server.Close()

	client := NewHTTPClient(clientCfg)

	baseURL := fmt.Sprintf("https://%s", listener.Addr().String())

	// 1. Test GET request
	resp, err := client.Get(baseURL + "/hello")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	getBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read get body: %v", err)
	}
	if string(getBody) != "Hello from TEE-TLS HTTP Server!" {
		t.Fatalf("unexpected get body: %s", string(getBody))
	}

	// 2. Test POST request
	postData := []byte("confidential inference payload")
	resp2, err := client.Post(baseURL+"/hello", "text/plain", bytes.NewReader(postData))
	if err != nil {
		t.Fatalf("HTTP POST failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp2.StatusCode)
	}
	postBody, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("read post body: %v", err)
	}
	if string(postBody) != "ECHO: confidential inference payload" {
		t.Fatalf("unexpected post body: %s", string(postBody))
	}
}

// TestTEETLS_ConnDeadlines verifies SetDeadline, SetReadDeadline, SetWriteDeadline behavior.
func TestTEETLS_ConnDeadlines(t *testing.T) {
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

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			// Complete handshake on server side so client Dial succeeds
			if tConn, ok := conn.(*Conn); ok {
				_ = tConn.Handshake()
			}
			// Keep connection open without writing any application data
			time.Sleep(500 * time.Millisecond)
		}
	}()

	clientConn, err := Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	// Set short read deadline
	clientConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 10)
	_, err = clientConn.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error on read, got nil")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected net timeout error, got: %v", err)
	}
}
