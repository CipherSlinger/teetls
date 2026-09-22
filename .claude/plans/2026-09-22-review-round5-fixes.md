# teetls review round 5 — fixes

Date: 2026-09-22
Scope: `/home/hjy/taa/teellm/teetls`

Round 5 re-read `verifier.go`, `config.go`, `transport.go` and the whole
`pkg/csvattest` package, then dispatched two concurrent subagents: one to
resolve the three ABI-dependent attestation findings against the Hygon CSV
reference, and one to apply the fail-fast and documentation fixes.

## Findings

| # | Finding | Severity | Action |
|---|---------|----------|--------|
| R5-1 | `VerificationResult.PubkeyDigest` (report offset 0x000) is parsed but never consumed. | info | none (see below) |
| R5-2 | `VerifyCertChain` validates CEK `PubKeyUsage`/`Sig1Usage`/`Sig2Usage` but only PEK `PubKeyUsage`. | low | none (see below) |
| R5-3 | PEK/CEK `sig2` signature region is never verified; only `sig1` is. | info | none (see below) |
| R5-4 | Sealing key (`Reserved2`) and full `rawReport` are retained in the exported `VerificationResult`. | low | already mitigated in round 3 (`zeroReserved2`); residual hygiene only |
| R5-5 | `Listen` defers two configuration errors to the first handshake: missing cert material, and strict mode + mutual attestation with an empty whitelist. | low | fix |
| R5-6 | No hostname / SNI / DNS-name verification; peer identity is measurement + ephemeral key only. | info | document only |
| R5-7 | `verifyChain=false` returns `ReportVerified=true` after only the PEK signature. | info | none (documented in R4-3) |

### ABI resolution (findings R5-1..R5-3)

Cross-checked against the Hygon-authored reference `openanolis/csv-rs`
(`src/api/guest/types.rs`, `src/certs/csv/cert/mod.rs`, `src/certs/mod.rs`)
and the Hygon verifier in `confidential-containers/trustee`. The Go offsets in
`constants.go` match the reference `#[repr(C)]` layouts exactly.

- **R5-1 — REDUNDANT.** The reference field is `user_pubkey_digest` ("Pubkey
  digest of the session used to secure communication between user/hypervisor
  and PSP"), not a PEK-key binding. It lies inside the PEK-signed region
  (`SignedSize=0xb4`) and the Hygon reference verifier also performs no
  cross-check. Cross-checking it against the PEK key would be *wrong*.
- **R5-2 — REDUNDANT.** The cert signature covers only `body` (`cert[0:0x414]`);
  the usage fields at `0x414`/`0x61c` are outside the signed region, hence
  unauthenticated metadata. The reference verifier validates no usage fields at
  all. The load-bearing check is the SM2 signature, which the Go code performs.
- **R5-3 — REDUNDANT (fail-closed).** `csv-rs` uses two sig slots; `sig2` is a
  second-issuer/rotation slot unused in the single-signed HRK→HSK→CEK→PEK chain
  (`sig2_usage = KeyUsageInvalid`). No public ABI material shows real hardware
  emitting `sig2`. Ignoring it can only reject valid future dual-signed reports,
  never accept an invalid one. The Go code is already stricter than the
  reference for CEK `sig2`.

None of the three is a real gap; no code change is warranted.

## Implementation

1. `transport.go`: in `Listen`, after `Validate()`, fail fast when neither
   `CertPEM`/`KeyPEM` nor `EvidenceProvider` is configured (mirrors
   `GetOrGenerateCertificateContext`), and when strict mode + mutual
   attestation has an empty `ExpectedMeasurements` whitelist. The client-side
   strict-mode empty-whitelist check already existed in `DialContext`.
2. `README.md`: add a Security Notes bullet stating there is no hostname / SNI /
   DNS-name verification; peer identity is the attestation measurement whitelist
   plus the ephemeral-key binding.

## Verification

- `gofmt -l .` (clean), `go vet ./...` (clean), `go test ./...` (pass).
