# teetls review round 4 — fixes

Date: 2026-09-22
Scope: `/home/hjy/taa/teellm/teetls`

Round 4 read the record, connection, handshake, certificate, transport,
config, evidence, provider and chain-verification layers end to end again,
this time against the already-patched tree (rounds 1–3 are committed). It
also probed the write path, which rounds 1–3 had not covered.

## Findings

| # | Finding | Severity | Action |
|---|---------|----------|--------|
| R4-1 | The record write path ignores the byte count returned by the underlying writer. `Conn.Write` (`conn.go`), `Conn.Close` (the close_notify write), `writePlaintextHandshakeMsg` and `writeEncryptedHandshakeMsg` all discard `n` and only test `err`. `io.Writer` requires a non-nil error on a short write, so this is unreachable for a conforming `net.Conn`, but the record stream is the security boundary and a buggy `net.Conn` has historically returned a short count with a nil error. On such a writer the record would be silently truncated and the peer would fail decryption with a confusing error, or worse, accept a truncated but MAC-valid prefix (impossible here, because the truncated record fails the AEAD open on the peer — but the local side would still have counted the bytes as sent). | low | fix |
| R4-2 | The handshake key schedule deviates from RFC 8446: the Finished keys are drawn from the same HKDF stream as the traffic keys (not derived from the transcript), and Finished is an HMAC over the raw transcript bytes rather than over the transcript hash. | info | document only |
| R4-3 | `VerifyReportData` / `VerifyReport` accept `verifyChain=false` and return a result with `ReportVerified=true` after checking only the report's self-asserted PEK signature. | info | none (caller explicitly opts out; teetls always passes `VerifyChain=true`) |

### Leads examined and rejected

- **`Conn.Write`/`Close` short write** — the actual defect, now fixed by `writeFull` (R4-1).
- **Finished key not transcript-bound (R4-2).** Not exploitable: the ECDHE shared secret is fresh every handshake, so no key is reusable across handshakes, and the Finished MAC still authenticates the transcript (its value is a PRF of the transcript under a key the attacker cannot derive). This is already covered by the README's "custom wire protocol" disclaimer.
- **`extractSM2PublicKey` reinterprets `*ecdsa.PublicKey` as SM2 without `IsOnCurve`.** Rejected in round 2; still no issue — the attestation binding ties the certificate key to the report, and `CertificateVerify` would fail for any key not actually signing with the SM2 curve.
- **`parseHygonPubKey` does not check `IsOnCurve`.** The public key comes from a chain-verified certificate (self-signed HRK, or HRK/HSK-signed intermediates), so an off-curve key cannot pass the chain signatures. gmsm's `Sm2Verify` also rejects rather than panics on an off-curve key (verified in round 2).
- **`computeECDHESharedSecret` point-at-infinity path.** Unreachable: `decodePublicKeySM2` rejects off-curve points (including the point at infinity) and sm2p256v1 has cofactor 1, so no non-trivial low-order point exists to force a zero shared secret.
- **`getEvidenceWithContext` goroutine on a non-`ContextEvidenceProvider`.** The result channel is buffered (cap 1), so the goroutine never blocks on send and there is no leak; the worst case is a bounded background hardware call after cancellation.
- **`Conn` concurrent read/write.** `readMu`/`writeMu` serialize same-direction access and the `RecordCipher` mutex serializes sequence-number updates; the `atomic.Bool` `handshakeDone` provides the happens-before edge between the handshake goroutine's cipher assignment and a later `Read`/`Write`/`Close`. `go test -race` is clean.
- **Certificate chain layout and report field offsets.** Re-verified: the PEK cert region `[OffsetPEKCert, OffsetPEKCert+CSVCertSize)` ends exactly at `OffsetChipID`, and `ParseReport` materialises exactly `CSVCertSize` bytes of unmasked PEK cert, so the round-3 length guard is correct and non-restrictive.

## Implementation

1. `handshake.go`: add `writeFull(w io.Writer, p []byte) error`, which returns `io.ErrShortWrite` when the writer stops short with a nil error. Use it in `writePlaintextHandshakeMsg` and `writeEncryptedHandshakeMsg`.
2. `conn.go`: use `writeFull` in `Conn.Write` and in `Conn.Close`'s close_notify write.
3. `handshake_test.go`: add `TestWriteFull` with a `shortWriter` that returns `len(p)-1` with a nil error, asserting the full-write path succeeds and the short-write path returns `io.ErrShortWrite`.

## Verification

- `gofmt -l .`, `go vet ./...`, `go test ./... -count=3`, `go test -race ./...`
- Cross-builds for linux/amd64, linux/arm64, darwin/arm64, windows/amd64
- `go vet -tags csv_hardware ./pkg/csvattest/`
- Parent `taa` module build and `go test ./...` (17 packages)
