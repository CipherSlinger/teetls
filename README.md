# teetls

[![Go Reference](https://pkg.go.dev/badge/github.com/CipherSlinger/teetls.svg)](https://pkg.go.dev/github.com/CipherSlinger/teetls)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

`teetls` is a lightweight, pure-Go TEE-TLS / RA-TLS-style transport that combines ShangMi cryptography with Hygon CSV remote attestation.

It provides `net.Conn`, `net.Listener`, and `net/http` integration where an ephemeral SM2 certificate key is cryptographically bound to a CSV attestation report. The verifier checks the report signature, the Hygon certificate chain, the public-key binding in `USER_DATA`, and the configured measurement whitelist.

> Compatibility note: this project uses TLS 1.3 concepts and ShangMi primitives, but the current wire protocol is custom and interoperates with `teetls` peers. It should not be described as wire-compatible with arbitrary RFC 8446 / RFC 8998 TLS implementations unless a standard-compatible handshake is implemented separately.

---

## Features

- **Pure Go**: no CGO or external C library dependency.
- **ShangMi primitives**:
  - SM2 ephemeral key agreement.
  - SM2 certificate signatures.
  - SM3 transcript, HMAC, HKDF, and public-key binding hashes.
  - SM4-GCM record encryption.
- **Hygon CSV remote attestation**:
  - CSV guest driver support in `pkg/csvattest` for `/dev/csv-guest` ioctls.
  - ASN.1/DER X.509 evidence extension (`1.3.6.1.4.1.58270.1.1`) carrying CSV reports and optional chain intermediates.
  - PEK signature verification over the report.
  - Hygon chain verification: trusted HRK -> HSK -> CEK -> PEK.
  - Public-key binding: report `USER_DATA[:32] == SM3(cert.RawSubjectPublicKeyInfo)`.
  - Measurement whitelist verification in strict mode.
- **Offline verification**:
  - Runtime verification does not require downloading Hygon certificates.
  - The HRK trust anchor must be embedded, pinned, or configured locally.
  - Peer-provided HRK material is not a trust anchor.
- **Mutual attestation**: optional bidirectional attestation where both endpoints present and verify evidence.
- **Go networking integration**: `Dial`, `Listen`, `NewHTTPTransport`, and `NewHTTPClient`.

---

## Trust Model & Key Separation

The identity authentication key is **not** the Hygon TEE hardware key. `teetls` generates an ephemeral SM2 key pair in the guest and binds that key to the CSV hardware report.

```
Trusted local HRK anchor
    signs
HSK / CEK intermediate bundle
    signs
PEK certificate embedded in CSV report
    verifies
CSV attestation report signature
    contains
USER_DATA = SM3(ephemeral certificate public key DER)
    binds
Ephemeral SM2 X.509 certificate
    authenticates
CertificateVerify signature in the teetls handshake
```

### Why not use the TEE hardware key directly?

1. Hardware private keys are not exportable to guest software.
2. CSV hardware signs structured attestation reports, not arbitrary TLS transcript data.
3. Ephemeral certificate keys keep handshake signing fast and allow short-lived RA-TLS identities.

### Two SM2 key roles

`teetls` uses two separate SM2 key roles:

1. **Ephemeral key agreement key**: exchanged in ClientHello/ServerHello and used to derive SM4-GCM traffic keys through HKDF-SM3.
2. **Certificate identity key**: embedded in the X.509 certificate and bound to the CSV report through `USER_DATA`. This key signs CertificateVerify.

SM4 traffic-key derivation does not need the certificate identity private key.

---

## Offline Hygon Certificate Verification

Deployments may run without network access. Verification is therefore fail-closed and local-first:

- Configure trusted HRK material with `Config.TrustedHRKCert`, `Config.HRKCertPath`, or `Config.CertDir`.
- Provide HSK/CEK intermediate material through `Config.HSKCekCertPath`, `Config.CertDir`, or the peer evidence extension.
- A peer can send HSK/CEK intermediates, but the verifier only accepts them if they chain to the local trusted HRK.
- A peer-supplied HRK is accepted only if it exactly matches the local trusted HRK.
- Missing chain material fails verification unless `InsecureSkipAttestationVerify` is explicitly enabled.

Expected enclave measurements are supplied in `Config.ExpectedMeasurements` and compared against the report measurement. In `ModeStrict`, an empty measurement whitelist is rejected for peer verification.

---

## Installation

```bash
go get github.com/CipherSlinger/teetls
```

---

## TCP Server Example

```go
package main

import (
    "log"
    "net"

    "github.com/CipherSlinger/teetls"
)

func main() {
    provider := teetls.NewHygonHardwareProvider(
        "/dev/csv-guest",
        "/etc/hygon/hrk.cert",
        "/etc/hygon/hsk_cek.cert",
    )

    cfg := &teetls.Config{
        Mode:             teetls.ModeStrict,
        EvidenceProvider: provider,
        HRKCertPath:      "/etc/hygon/hrk.cert",
        HSKCekCertPath:   "/etc/hygon/hsk_cek.cert",
    }

    listener, err := teetls.Listen("tcp", ":8443", cfg)
    if err != nil {
        log.Fatalf("listen: %v", err)
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("accept: %v", err)
            continue
        }
        go handleConn(conn)
    }
}

func handleConn(conn net.Conn) {
    defer conn.Close()

    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return
    }
    _, _ = conn.Write([]byte("Hello from secure CSV enclave: " + string(buf[:n])))
}
```

---

## TCP Client Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/CipherSlinger/teetls"
)

func main() {
    cfg := &teetls.Config{
        Mode: teetls.ModeStrict,
        ExpectedMeasurements: []string{
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        },
        HRKCertPath:    "/etc/hygon/hrk.cert",
        HSKCekCertPath: "/etc/hygon/hsk_cek.cert",
    }

    conn, err := teetls.Dial("tcp", "server.enclave.local:8443", cfg)
    if err != nil {
        log.Fatalf("dial: %v", err)
    }
    defer conn.Close()

    if _, err := conn.Write([]byte("Ping from client")); err != nil {
        log.Fatalf("write: %v", err)
    }

    resp := make([]byte, 1024)
    n, err := conn.Read(resp)
    if err != nil {
        log.Fatalf("read: %v", err)
    }
    fmt.Printf("Server response: %s\n", string(resp[:n]))
}
```

---

## HTTP Client Integration

```go
client := teetls.NewHTTPClient(&teetls.Config{
    Mode: teetls.ModeStrict,
    ExpectedMeasurements: []string{expectedMeasurementHex},
    HRKCertPath:          "/etc/hygon/hrk.cert",
    HSKCekCertPath:       "/etc/hygon/hsk_cek.cert",
})

resp, err := client.Get("https://server.enclave.local:8443/api/v1/secure-data")
```

For custom transport settings:

```go
transport := teetls.NewHTTPTransport(cfg)
```

---

## Testing and Debugging Modes

### MockEvidenceProvider

`NewMockEvidenceProvider` creates cryptographically valid mock evidence for tests. The generated mock HRK is not a real Hygon root and must only be used as an explicit test trust anchor, for example:

```go
provider := teetls.NewMockEvidenceProvider()
cfg := &teetls.Config{
    Mode:                 teetls.ModeStrict,
    EvidenceProvider:     provider,
    TrustedHRKCert:       provider.TrustedHRKCert(),
    ExpectedMeasurements: []string{provider.GetMeasurementHex()},
}
```

### InsecureSkipAttestationVerify

`InsecureSkipAttestationVerify` bypasses attestation verification and should be used only for local debugging or tests. It must not be enabled in production.

---

## Package Structure

- `conn.go`, `handshake.go`: custom TEE-TLS handshake and `net.Conn` wrapper.
- `record.go`: TLS 1.3-style record protection with SM4-GCM.
- `cert.go`: SM2 certificate generation and public-key SM3 binding.
- `evidence.go`: ASN.1 encoding and decoding of CSV evidence extensions.
- `provider.go`: evidence provider abstraction, Hygon hardware provider, and mock provider.
- `verifier.go`: certificate/evidence verification, public-key binding, measurement checks.
- `transport.go`: `Dial`, `Listen`, and HTTP integration.
- `pkg/csvattest`: CSV report parsing, PEK signature verification, chain verification, and device access helpers.

---

## Common Commands

```bash
# Run tests
go test ./...

# Run race tests
go test -race ./...

# Run vet
go vet ./...
```

---

## Security Notes

- Keep the trusted HRK anchor immutable and provisioned out-of-band.
- Keep `ExpectedMeasurements` up to date with approved enclave builds.
- Treat `ModePermissive` as an audit/debugging mode; it still verifies cryptographic evidence but does not reject measurement mismatches.
- Treat `InsecureSkipAttestationVerify` as unsafe outside controlled tests.
- This repository does not currently claim general wire interoperability with `crypto/tls` or third-party TLS 1.3 stacks.
