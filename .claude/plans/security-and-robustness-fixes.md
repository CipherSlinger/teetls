# Implementation Plan: Fix Security, Cryptographic, and Robustness Defects in teetls

## Context
A thorough review of `teetls` identified critical cryptographic vulnerabilities, missing verification steps in the hardware trust chain, configuration bypasses, and network robustness issues:
1. **GCM Nonce Reuse (P0)**: Sequence numbers were reset to 0 after the handshake while continuing to use the same keys and IVs, violating GCM security requirements and enabling Joux Forbidden Attacks.
2. **Unverified Attestation Reports & Chains (P0)**: `verifier.go` checked only `USER_DATA` and `MEASURE`, but never verified the report's PEK signature or the Hygon certificate chain (HRK &rarr; HSK &rarr; CEK &rarr; PEK), allowing forged mock reports to pass.
3. **`ModeStrict` Bypass on Missing Measurements (P1)**: If `ExpectedMeasurements` was empty in `ModeStrict`, measurement verification was silently skipped.
4. **`DialContext` Handshake Hanging (P1)**: The context deadline was not applied to `conn.Handshake()`, allowing uncooperative servers to hang clients indefinitely.
5. **Server Performance Bottleneck (P2)**: Servers without static certs invoked the hardware IOCTL on every incoming connection instead of caching ephemeral certificates.
6. **Static Nonce in Driver (P2)**: Hardware driver calls used an all-zero static nonce, sacrificing fresh session proof.
7. **Certificate Expiry Ignored (P2)**: Peer X.509 certificates were not checked against `NotBefore`/`NotAfter`.
8. **Missing `close_notify` (P2)**: Connections were closed abruptly via TCP without a TLS alert record, vulnerable to truncation.
9. **Record Header Inconsistency (P3)**: `ClientHello` and `ServerHello` lacked standard 5-byte `TLSPlaintext` record encapsulation.

---

## Recommended Architecture & Changes

### 1. Key Schedule Separation (`handshake.go`)
- Split key derivation into two distinct stages:
  - **Handshake Traffic Keys**: Derived using HKDF-SM3 with info `"tls13-rfc8998-handshake-traffic"` for `ClientHandshakeWriteKey`, `ServerHandshakeWriteKey`, `ClientHandshakeWriteIV`, `ServerHandshakeWriteIV`, and Finished HMAC keys.
  - **Application Traffic Keys**: Derived using HKDF-SM3 over the shared secret combined with the final transcript hash and info `"tls13-rfc8998-application-traffic"` for `ClientAppWriteKey`, `ServerAppWriteKey`, `ClientAppWriteIV`, `ServerAppWriteIV`.
- Handshake messages are encrypted/decrypted using `HandshakeTrafficKeys`.
- Upon handshake completion, instantiate brand new `RecordCipher` instances using `ApplicationTrafficKeys` (starting at `seq = 0`).
- Remove `.Reset()` on handshake ciphers. Completely eliminates GCM nonce reuse.

### 2. Complete PEK Signature & Certificate Chain Verification (`verifier.go`)
- Update `VerifyPeerCertificateAndEvidence` to call `csvattest.VerifyReportWithOptions`:
  1. Verify the PEK signature on the attestation report using the report's embedded PEK certificate.
  2. If certificate chain data is provided (`evidence.HRKCert`, `evidence.HSKCekCert`) or configured in `Config`, verify the full chain: HRK (self-signed) &rarr; HSK (signed by HRK) &rarr; CEK (signed by HSK) &rarr; PEK (signed by CEK).
  3. Validate that `USER_DATA` matches the SM3 hash of the peer's SM2 public key DER.
  4. Verify enclave measurement against `ExpectedMeasurements`.
- Update `MockEvidenceProvider` (in `provider.go` / `pkg/csvattest`) to generate valid signed mock reports with an authentic mock SM2 cert chain, ensuring both real and mock environments undergo full cryptographic verification.

### 3. Strict Mode Enforcement (`verifier.go`, `config.go`)
- In `config.go`: Update `Validate()` to require `len(ExpectedMeasurements) > 0` when `Mode == ModeStrict` and `!InsecureSkipAttestationVerify`.
- In `verifier.go`: In `ModeStrict`, if `len(cfg.ExpectedMeasurements) == 0`, return `ErrMeasurementMismatch` immediately rather than skipping the check.

### 4. `DialContext` Handshake Deadline (`transport.go`)
- In `DialContext`: Before invoking `conn.Handshake()`, check if `ctx.Deadline()` or `cfg.Timeout > 0` is set.
- Apply `rawConn.SetDeadline(...)` covering the handshake operation, and clear it afterwards (`defer rawConn.SetDeadline(time.Time{})`).
- Handle context cancellation cleanly.

### 5. Server Ephemeral Certificate Caching (`transport.go`, `handshake.go`)
- Introduce a thread-safe `CertCache` in `Config` or `listener`.
- When a server listener is created with `EvidenceProvider` and no static `CertPEM`, generate the ephemeral certificate and CSV evidence once and cache it for a configurable TTL (default 1 hour), renewing only upon expiration.
- Avoid calling `/dev/csv-guest` hardware IOCTL on every accepted TCP connection.

### 6. Cryptographic Random Nonce in Provider (`provider.go`)
- Replace `nonce := make([]byte, csvattest.NonceSize)` in `HygonHardwareProvider.GetEvidence` with `io.ReadFull(rand.Reader, nonce)`.

### 7. Peer Certificate Validity Verification (`verifier.go`)
- In `VerifyPeerCertificateAndEvidence`, check `time.Now()` against `cert.NotBefore` and `cert.NotAfter`.
- Return a descriptive error if the certificate has expired or is not yet valid.

### 8. Graceful `close_notify` Alert (`conn.go`)
- In `Conn.Close()`, if the handshake completed and connection is active:
  - Seal and transmit a 2-byte TLS alert record: `[1, 0]` (`RecordTypeAlert`, `close_notify`) using `outCipher`.
  - Close `rawConn`.
- In `Conn.Read()`, when encountering `RecordTypeAlert`, return `io.EOF`.

### 9. Unified `TLSPlaintext` Record Framing (`handshake.go`)
- Wrap `ClientHello` and `ServerHello` in standard 5-byte `TLSPlaintext` record headers (`RecordTypeHandshake` 22, legacy version `0x0303`, length).
- Unified framing ensures every record on the wire has a consistent 5-byte header, simplifying stream processing and network debugging.

---

## Critical Files to Modify
- `handshake.go`: Key schedule separation, `TLSPlaintext` framing for Client/ServerHello, record cipher lifecycle.
- `verifier.go`: PEK signature verification, cert chain validation, `ModeStrict` check, certificate validity time check.
- `provider.go`: Random nonce in hardware provider, signed mock evidence generation in `MockEvidenceProvider`.
- `config.go`: `ModeStrict` validation, certificate cache fields, optional CA cert path configs.
- `transport.go`: Handshake deadline propagation in `DialContext`, cert cache integration in `Listen`.
- `conn.go`: `close_notify` alert on `Close()`.
- `teetls_test.go`, `verifier_test.go`: Add test cases for all new security guarantees.

---

## Verification Plan
1. **Unit & Integration Tests**:
   - `go test -v ./...`
   - `go test -race ./...`
2. **Security & Cryptographic Verification Tests**:
   - Test that application traffic keys differ from handshake traffic keys and application sequence numbers start at 0 without nonce collision.
   - Test that tampered PEK signatures or broken certificate chains are rejected by `VerifyPeerCertificateAndEvidence`.
   - Test that `ModeStrict` with empty `ExpectedMeasurements` is rejected.
   - Test that expired certificates are rejected.
   - Test that `DialContext` with a blocked/stalled server respects the context deadline and returns a timeout error.
   - Test that `conn.Close()` sends `close_notify` and peer receives `io.EOF`.
   - Test server certificate caching under multiple concurrent connections.
