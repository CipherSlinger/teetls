# teetls review round 3 — fixes

Date: 2026-09-22
Scope: `/home/hjy/taa/teellm/teetls`

Round 3 focused on the exported surface of `pkg/csvattest` and on the remaining
test files, driven by empirical probes (a temporary test that calls each exported
parser with a short buffer and records whether it panics or errors) rather than by
reading alone.

## Findings

| # | Finding | Severity | Action |
|---|---------|----------|--------|
| R3-1 | `VerifyReportPEKSignature` (`pkg/csvattest/verify.go:193`) validates `res == nil` and `len(res.rawReport) < SignedSize`, but then evaluates `res.PEKCert[OffsetCSVPubKey:]` and `ParseHygonSignature(res.Signature)` without checking those fields. Both panic on short input. Confirmed by probe: `PEKCert = nil` panics with `slice bounds out of range [16:0]`, `PEKCert = make([]byte, 4)` with `[16:4]`. `VerificationResult` is exported with settable fields and `VerifyReportPEKSignature` is exported and documented as taking one, so a caller that builds a result directly gets a panic instead of an error. The `Signature` path is reachable the same way once a valid PEK certificate is present, because `ParseHygonSignature` slices `sig[72:104]`. | medium | fix |
| R3-2 | `ParseHygonSignature` (`verify.go:484`) is the only fixed-layout parser in the package with no length precondition. Its immediate siblings `ParseRootCertDetails` and `ParseCSVCertDetails` both check length and return an error. Confirmed by probe: `ParseHygonSignature(make([]byte, 64))` panics. Internal callers are safe — `ParseReport` always materialises a 144-byte `Signature` and certificate signature regions are `HrkCertSize`/`CSVCertSize` — so this is an exported-contract gap, not a reachable in-package bug. | low | fix (fail closed, keep the signature) |
| R3-3 | `GetSealingKeyIOCTL` (`ioctl_linux.go:56`) leaves the sealing key in the heap-allocated `report` slice after `ExtractSealingKey`. `GetAttestationReportIOCTL` zeroes the same field via `zeroReserved2` before copying out, so the two paths are asymmetric: the sealing-key path leaves key material in a buffer that outlives the call. | low | fix |
| R3-4 | `github.com/tjfoc/gmsm v1.4.1` is the newest release on that module path (the upstream repository was archived and development moved to `github.com/emmansun/gmsm`). There is nothing to upgrade to in place. | info | document only |
| R3-5 | Test coverage in `cert_test.go`, `record_test.go`, `teetls_test.go`, `pkg/csvattest/{ioctl_linux,client,ioctl_unsupported}_test.go` is non-vacuous. No skips remain anywhere in the repository. | — | none |

### Leads examined and rejected

- **`Sm2Verify` range checks.** Read gmsm v1.4.1 `sm2/sm2.go`: `Sm2Verify` rejects `r < 1`, `s < 1`, `r >= N`, `s >= N` and `t == 0`. A zero `r`/`s` therefore fails closed. This is what makes the R3-2 fix safe: returning zero values for a short buffer cannot cause an acceptance.
- **SM2 user ID.** `PrivateKey.Sign` and `PublicKey.Verify` both resolve a nil user ID to `default_uid` (`"1234567812345678"`), and `Sm2Verify` does the same for an empty `uid`. The handshake's sign/verify pair is therefore self-consistent. A certificate declaring a zero-length user ID is verified under `default_uid`, but the user ID lives inside the CEK-signed region of the PEK certificate, so an attacker cannot inject one. Not exploitable.
- **`PublicKey.Verify` discards trailing bytes.** `asn1.Unmarshal`'s `rest` is ignored, so bytes after the DER signature are not rejected. Not exploitable: the handshake's Finished MAC covers the exact `sigBody` bytes.
- **`defer c.ops.munmap(page)` / `defer dev.Close()` discard errors**, and `getAttestationReportIOCT` has an unusual trailing `T`. Cosmetic; left unchanged so the fixed ABI constant is not churned.
- **`UnmaskWords` with a non-multiple-of-4 length** leaves 1–3 trailing bytes unmasked. No caller passes such a length; every call site uses a 4-byte multiple.
- **`Client.userData()` reading `ATTESTATION_USERDATA`** is fail-closed through the public-key binding, so it is not a trust gap. Already covered by `TestUserDataDefaultsAndValidation`.

## Implementation

1. `pkg/csvattest/verify.go`: at the top of `VerifyReportPEKSignature`, check `len(res.PEKCert) >= CSVCertSize` and `len(res.Signature) >= OffsetHygonSigS+32`, returning `ErrShortBuffer` with the actual and required sizes. Placed before the `parseHygonPubKey` call so the error names the real problem. Requiring the full `CSVCertSize` rather than the 16 bytes the slice needs is deliberate: it also covers the reads `parseHygonPubKey` performs inside the certificate, and `ParseReport` always supplies exactly that.
2. `pkg/csvattest/verify.go`: make `ParseHygonSignature` return `(0, 0)` when `len(sig) < OffsetHygonSigS+32` and document the precondition. Zero values are the fail-closed choice because `Sm2Verify` rejects them; the exported two-value signature is preserved.
3. `pkg/csvattest/ioctl_linux.go`: `defer clear(report)` immediately after `fetchReportIOCTL` succeeds in `GetSealingKeyIOCTL`, and `clear(key)` after copying into the caller's buffer.
4. Tests: `TestVerifyReportPEKSignature_RejectsShortFields` builds a valid report with `newTestReport(t, false)`, parses it to obtain a genuine PEK certificate, then asserts that a short `PEKCert` and a short `Signature` both return `ErrShortBuffer` rather than panicking. `TestParseHygonSignature_ShortBuffer` covers the zero-value contract directly, including that a zero `r`/`s` fails `sm2.Sm2Verify`. Parsing a real report matters: with a zeroed PEK certificate the short-`Signature` case is masked by a public-key parse failure and passes for the wrong reason.

R3-2 is verified by inspection only. The cleared slice is a function-local inside `GetSealingKeyIOCTL`, and the `fetchReportIOCTL` copy it clears is not reachable from a test, so no honest assertion can be made about it. `TestGetSealingKeyIOCTLWithFakeDevice` continues to pin the observable contract — that the key round-trips into the caller's buffer. The mmap'd page is left uncleared on both the sealing-key and attestation-report paths, which is pre-existing and symmetric; only the heap copy is treated here, matching what `GetAttestationReportIOCTL` already does.

## Verification

- Confirm each new test fails against the unpatched code (temporarily revert, observe the panic, restore).
- `gofmt -l .`, `go vet ./...`, `go test ./... -count=3`, `go test -race ./...`
- Cross-builds for linux/amd64, linux/arm64, darwin/arm64, windows/amd64
- `go vet -tags csv_hardware ./pkg/csvattest/`
- `govulncheck ./...` if it can be fetched
