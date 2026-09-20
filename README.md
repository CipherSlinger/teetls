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
  - ASN.1/DER X.509 evidence extension (`1.3.6.1.4.1.58270.1.1`) embedding CSV reports and certificate chains into ephemeral certificates.
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

### Trust Model & Key Separation

A fundamental design aspect of RA-TLS is that **the identity authentication key is NOT directly the Hygon TEE hardware key**. Instead, an ephemeral SM2 key pair is generated in enclave memory and cryptographically bound to the TEE hardware report.

```
+-----------------------------------------------------------+
| Hygon Root CA (HRK)                                       |
|   │ signs                                                 |
| Hygon Sign Key (HSK) & Chip Endorsement Key (CEK)         |
|   │ signs                                                 |
| Platform Endorsement Key (PEK) ── Hardware Private Key    |
+──────────────────────────┬────────────────────────────────+
                           │ Signs CSV Report
                           ▼
+───────────────────────────────────────────────────────────+
| Hygon CSV Attestation Report                              |
|   - MEASURE   : Enclave launch digest (code integrity)    |
|   - USER_DATA : SM3(Ephemeral Certificate SM2 Public Key) |
+──────────────────────────┬────────────────────────────────+
                           │ Cryptographic Hash Binding
                           ▼
+───────────────────────────────────────────────────────────+
| Ephemeral X.509 Certificate (SM2 Public Key)              |
|   - Verifies TLS 1.3 CertificateVerify signature          |
+-----------------------------------------------------------+
```

#### Why not use the TEE hardware key directly?
1. **Hardware Key Isolation**: Hardware private keys (CEK, PEK) reside exclusively inside the Hygon Security Processor (PSP) / secure hardware and can never be exported to guest software.
2. **Preventing Signature Oracles**: TEE hardware only signs structured attestation reports; it intentionally does not expose arbitrary data signing primitives to prevent attackers from abusing hardware keys to forge platform or firmware credentials.
3. **High Handshake Performance**: Generating and signing with in-memory SM2 keys avoids costly hardware context switches and ioctl traps on every TLS connection.

#### Two SM2 Keys in RFC 8998 TLS 1.3
Standard RFC 8998 TLS 1.3 maintains two distinct SM2 key pairs with strict separation of duties:
1. **Ephemeral Key Share (`curveSM2`)**: Generated dynamically during `ClientHello`/`ServerHello`. Used solely for ECDHE key exchange and HKDF-SM3 derivation of SM4-GCM record encryption keys, ensuring **Perfect Forward Secrecy (PFS)**.
2. **Certificate Identity Key (`sm2sig_sm3`)**: Embedded in the X.509 certificate and bound to the CSV report's `USER_DATA`. Used strictly for `CertificateVerify` signatures to authenticate the enclave identity. The SM4 key derivation phase does not depend on or require knowledge of this certificate key.

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
