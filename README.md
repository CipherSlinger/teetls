# teetls

[![Go Reference](https://pkg.go.dev/badge/github.com/CipherSlinger/teetls.svg)](https://pkg.go.dev/github.com/CipherSlinger/teetls)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

`teetls` is a lightweight, pure-Go implementation of **TEE-TLS** combining **TLS 1.3 ShangMi (SM) cipher suites (RFC 8998)** with **Hygon CSV (China Secure Virtualization) Remote Attestation**.

It provides confidential computing communication channels where TLS peer certificates are cryptographically bound to hardware-rooted TEE attestation reports, guaranteeing workload identity and enclave integrity without external proxy dependencies or CGO bindings.

---

## Features

- **Pure-Go Implementation**: 100% Go with zero CGO dependencies or external C libraries.
- **RFC 8998 Compliant**: TLS 1.3 ShangMi cipher suite (`TLS_SM4_GCM_SM3`, `0x00c6`) using SM2 key exchange, SM3 hash, and SM4-GCM record encryption.
- **Hygon CSV Remote Attestation**:
  - Embedded CSV guest driver (`pkg/csvattest`) supporting direct `/dev/csv-guest` ioctls.
  - ASN.1/DER X.509 evidence extension (`1.3.6.1.4.1.58287.1.1`) embedding CSV reports and certificate chains into ephemeral certificates.
  - Anti-MITM public key binding: verifies that the CSV report's `USER_DATA` matches the SM3 digest of the peer's SM2 public key.
  - Comprehensive certificate chain verification (HRK &rarr; HSK &rarr; CEK &rarr; PEK).
  - Flexible measurement verification: **Strict** mode (rejects unauthorized measurements) and **Permissive** mode (logs warnings for audit).
- **Mutual Attestation (mTLS)**: Supports unidirectional (client verifies server) and bidirectional (both sides verify each other) attestation.
- **Drop-in Standard Library Compatibility**: Exposes `net.Conn`, `net.Listener`, and `http.RoundTripper` for seamless integration with standard Go networking and `net/http`.

---

## Architecture Overview

```
                   Client Enclave                                    Server Enclave
               +--------------------+                            +--------------------+
               |    teetls Client   |                            |    teetls Server   |
               +--------------------+                            +--------------------+
                         |                                                 |
                         | 1. ClientHello (SM2 Key Share)                  |
                         |------------------------------------------------>|
                         |                                                 |
                         | 2. ServerHello, EncryptedExtensions,            |
                         |    Certificate (SM2 + CSV Evidence Extension),  |
                         |    CertificateVerify, Finished                  |
                         |<------------------------------------------------|
                         |                                                 |
                         | [Verify Server CSV Attestation]                 |
                         |  - Check PEK signature over report              |
                         |  - Check report USER_DATA == SM3(ServerPubDER)  |
                         |  - Verify Hygon cert chain (HRK->HSK->CEK->PEK) |
                         |  - Validate enclave measurement against policy  |
                         |                                                 |
                         | 3. [Optional] Client Certificate (CSV Evidence),|
                         |    CertificateVerify, Finished                  |
                         |------------------------------------------------>|
                         |                                                 |
                         |    [Server verifies Client CSV Evidence]        |
                         |                                                 |
                         | 4. Bidirectional Encrypted Application Data     |
                         |<===============================================>|
```

---

## Getting Started

### Installation

```bash
go get github.com/CipherSlinger/teetls
```

### Server Example

```go
package main

import (
	"log"

	"github.com/CipherSlinger/teetls"
)

func main() {
	// 1. Initialize Hygon CSV evidence provider (or NewMockEvidenceProvider for testing)
	provider, err := teetls.NewHygonHardwareProvider()
	if err != nil {
		log.Fatalf("failed to initialize evidence provider: %v", err)
	}

	// 2. Configure TEE-TLS server
	config := &teetls.Config{
		Provider: provider,
	}

	// 3. Listen on TCP socket
	listener, err := teetls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn *teetls.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	conn.Write([]byte("Hello from secure CSV enclave: " + string(buf[:n])))
}
```

### Client Example

```go
package main

import (
	"fmt"
	"io"
	"log"

	"github.com/CipherSlinger/teetls"
)

func main() {
	// Configure client with expected server measurements
	config := &teetls.Config{
		ExpectedMeasurements: []string{
			"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
		},
		StrictMeasurement: true,
	}

	conn, err := teetls.Dial("tcp", "server.enclave.local:8443", config)
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Ping from client"))
	if err != nil {
		log.Fatalf("write failed: %v", err)
	}

	resp := make([]byte, 1024)
	n, _ := conn.Read(resp)
	fmt.Printf("Server response: %s\n", string(resp[:n]))
}
```

### HTTP Client Integration

Use `teetls.Transport` for standard `net/http` requests over TEE-TLS:

```go
client := &http.Client{
	Transport: teetls.NewTransport(&teetls.Config{
		ExpectedMeasurements: []string{expectedMeasurementHex},
		StrictMeasurement:    true,
	}),
}

resp, err := client.Get("https://server.enclave.local:8443/api/v1/secure-data")
```

---

## Package Structure

- `.` (`github.com/CipherSlinger/teetls`):
  - `conn.go`, `handshake.go`: RFC 8998 TLS 1.3 handshake and connection wrapper.
  - `record.go`: TLS 1.3 record layer encryption and decryption using SM4-GCM.
  - `cert.go`: SM2 certificate generation, PEM formatting, and public key SM3 digest computation.
  - `evidence.go`: ASN.1 encoding and decoding of CSV attestation evidence extensions.
  - `provider.go`: `EvidenceProvider` abstraction, Hygon hardware driver integration, and mock provider.
  - `verifier.go`: Peer certificate verification, public key binding validation, and enclave measurement checking.
  - `transport.go`: `http.RoundTripper` implementation for `net/http`.
  - `config.go`: TLS and attestation configuration options.
- `pkg/csvattest`:
  - Standalone Hygon CSV guest attestation driver and verification package.
  - Linux `ioctl` interactions (`/dev/csv-guest`).
  - Hygon certificate chain validation (HRK/HSK/CEK/PEK).
  - Session MAC and MNonce verification.

---

## Testing

Run all unit and integration tests:

```bash
go test -v ./...
```

---

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
