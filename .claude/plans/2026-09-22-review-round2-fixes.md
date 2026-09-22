# teetls review round 2 — fixes

Date: 2026-09-22
Scope: `/home/hjy/taa/teellm/teetls`

## Findings carried into this plan

| # | Finding | Severity | Action |
|---|---------|----------|--------|
| F1 | `Config.ExpectedMeasurements` entries are never validated. The comparison is `strings.EqualFold(exp, hexMeas)` where `hexMeas` is always 64 lowercase hex chars, so any entry that is not 64 hex characters can never match. A typo (wrong length, `0x` prefix, stray whitespace, or the empty string that `HygonHardwareProvider.GetMeasurementHex()` returns when the ioctl fails) surfaces as a late `ErrMeasurementMismatch` on every handshake instead of a config error at `Dial`/`Listen`. | medium | fix |
| F2 | `CSVEvidenceExtension.Version` is decoded but never validated or consumed. `EncodeCSVEvidence` normalises 0 to 1, but `DecodeCSVEvidence` accepts any value, including 99 and -5. Nothing reads the field today, so the impact is latent: the byte comes from the peer's certificate and any future code that branches on it would branch on attacker-controlled data. The ASN.1 tag is `optional,default:1`, so an absent field and an explicit 1 are indistinguishable after decoding. | low (latent) | fix |
| F3 | `TestLoadCertChainFromFiles_Success` (`pkg/csvattest/verify_test.go`) skips unconditionally: it looks for `deploy/certs/hrk.cert` and that directory does not exist in the repository. The test never runs, so the real-file load path is untested. | low | fix |
| F4 | Neither the root `teetls` package nor `pkg/csvattest` has a package doc comment, so `go doc` and pkg.go.dev show no package summary. | low | fix |
| F5 | `HygonHardwareProvider.GetMeasurementHex()` performs a full hardware attestation and discards every error, returning `""`. Callers who build a whitelist from it silently get `[""]`. | low | document (the interface has no error return, and F1 turns the bad value into a loud config error) |
| F6 | `README.md` states that `Config.Timeout` "bounds the handshake on both sides". True through `Dial`/`Listen`, but `ClientHandshake`/`ClientHandshakeContext` called directly do not set a deadline; only the server does. | low | document |
| F7 | `pkg/csvattest` `verify.go` / `report.go`: no new findings. `VerifySessionMAC` and `VerifyMNonce` are both called from `ioctl_linux.go`. | — | none |

### Leads examined and rejected

- **Off-curve peer public key.** `extractSM2PublicKey` (`handshake.go:204`) does not check `IsOnCurve` for the certificate key, unlike `decodePublicKeySM2`, and it also reinterprets any `*ecdsa.PublicKey` as SM2 regardless of the certificate's declared curve. Probed gmsm v1.4.1 directly: `PublicKey.Verify`, `sm2.Sm2Verify` and the degenerate `(0,0)` key all return `false` without panicking, so there is no crash and no acceptance. SM2 and NIST P-256 share the same `a` coefficient but differ in `b`, so the curves share no affine points and a P-256 key can never be reinterpreted as a valid SM2 key. No defect.
- **`Conn.Read` skipping zero-length records.** The `continue` at `conn.go:187` is unbounded, but an empty record costs the sender ~22 bytes of traffic for one AEAD open, an amplification of roughly 2x over simply sending the same volume of real data, and any caller-supplied deadline bounds the loop. `Read` is expected to block until data arrives regardless. Not a defect, so behaviour is left unchanged to avoid breaking a peer that emits pad records.
- **Per-`Config` certificate cache and forward secrecy.** The ECDHE ephemeral key is generated fresh in every handshake (`handshake.go:343` and `:619`), so the cached identity certificate does not weaken traffic-key uniqueness.
- **Transcript consistency.** The server's expected client Finished tag is computed over the same message sequence as the client's, and both sides derive the application keys from a transcript that includes the client Finished. Verified by reading both sides end to end.
- **Handshake record bounds.** `writePlaintextHandshakeMsg` refuses a message over `MaxPlaintextLength`; `readPlaintextHandshakeMsg` and `encryptedHandshakeReader` both cap the assembled buffer at 2 MiB and reject excess data.

## Implementation

1. `config.go`: add `validateExpectedMeasurements([]string) error` using `csvattest.HashSize*2` and `encoding/hex`. Call it from `Config.Validate()`. Each entry must be exactly 64 hex characters; case is free because the comparison uses `EqualFold`. This cannot reject any entry that could have matched: an entry of any other length or with a non-hex character can never equal a 64-character hex digest.
2. `verifier.go`: call the same helper from `normalizedVerifyConfig`, so `VerifyPeerCertificateAndEvidence` — which is exported and reachable without `Validate` — reports the same error.
3. `evidence.go`: export `EvidenceVersion = 1`. `EncodeCSVEvidence` normalises 0 to 1 before validating; `validateEvidenceExtension` rejects any version other than `EvidenceVersion`, so an unknown version fails closed on both encode and decode.
4. `provider.go`: document that `GetMeasurementHex` returns `""` on failure and that `""` is rejected by `Config.Validate`. Also add a package doc comment in a new `doc.go` for both packages.
5. `pkg/csvattest/verify_test.go`: rewrite `TestLoadCertChainFromFiles_Success` to build fixtures in `t.TempDir()` from `MockAttestationAuthority`, matching the pattern already used by `TestVerifyReportWithOptions_CustomPaths`. No skip.
6. Tests: extend `TestConfig_Validate` with the rejected measurement shapes, add `TestVerifyPeerCertificate_RejectsMalformedMeasurements`, and extend the evidence tests with a version-rejection case. Fix the incidental `"non-matching-measurement"` literal in `TestVerifyPeerCertificate_InsecureSkip` to a well-formed 64-hex string, since that test is about `InsecureSkipAttestationVerify` and not about measurement syntax.
7. `README.md`: state the measurement format and that it is validated at configuration time, tighten the `Config.Timeout` sentence, and note that the evidence version is validated.

## Verification

- `gofmt -l .`, `go vet ./...`
- `go test ./...` and `go test -race -count=1 ./...`
- Cross-builds for linux/amd64, linux/arm64, darwin/arm64, windows/amd64
- `go vet -tags csv_hardware ./pkg/csvattest/`
- Build and test the parent `taa` module, which links teetls through a `replace` directive and passes measurements through `internal/config`.
