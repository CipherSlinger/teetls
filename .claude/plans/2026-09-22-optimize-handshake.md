# teetls handshake optimizations

Date: 2026-09-22
Scope: `/home/hjy/taa/teellm/teetls`

Three maintenance items identified in the round-5 follow-up review, implemented
together. None changes the wire protocol or the key schedule.

## Items

1. **Deduplicate certificate preparation.** `prepareServerCertificate(Context)`
   and `prepareClientCertificate(Context)` were identical except for the role
   label in their error strings, and the non-context wrappers were dead code.
   Replaced all four with a single `prepareCertificate(ctx, cfg, role)`.

2. **Extract a transcript helper type.** Both handshakes accumulated the
   transcript in a raw `bytes.Buffer` and repeated `encodeHandshakeMsg(type,
   body)` at every call site, with two identical "snapshot before signature"
   copy blocks and a duplicated `sm3.Sm3Sum(...)` final hash. Replaced these
   with a `handshakeTranscript` type exposing `Write` (header + body),
   `WriteRaw` (ClientHello/ServerHello wire bytes), `Snapshot` (copy for
   CertificateVerify/Finished signing), and `Hash` (SM3 digest).

3. **Make client mutual attestation authoritative.** The client's request to
   attest itself is a plaintext byte in the ClientHello and was previously
   unauthenticated, so an on-path attacker could clear it and silently skip
   client attestation. The client now rejects with
   `ErrMutualAttestationNotConfirmed` when it set `VerifyMutualAttestation` but
   the server's authenticated EncryptedExtensions does not confirm mutual
   attestation.

## Verification

- `gofmt -l .` (clean), `go vet ./...` (clean).
- `go test ./...` and `go test -race ./...` (pass), including the new
  `TestMutualAttestationDowngradeRejected`, which flips the ClientHello flag
  through a `flagFlipConn` and asserts the client rejects the downgrade.
