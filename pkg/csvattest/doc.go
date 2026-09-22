// Package csvattest parses, verifies and retrieves Hygon CSV attestation
// reports, and exposes the certificate-chain and sealing-key helpers that the
// teetls package builds on.
//
// A report is a fixed-layout binary structure (ReportSize bytes) containing the
// measurement, the VM identity, a USER_DATA field, and a PEK certificate. Most
// of the interesting fields are masked with the report's A nonce and must be
// unmasked with UnmaskWords before use. ParseReport unmaskes and parses in one
// step; VerifyReportWithOptions additionally checks the PEK signature and the
// HRK -> HSK -> CEK -> PEK chain.
//
// Only the first SignedSize bytes of a report are covered by the PEK signature.
// Fields past that offset, including the A nonce, the PEK certificate, the
// ChipID and the MAC, are authenticated by other means and must not be trusted
// on their own; see VerifyReportPEKSignature.
//
// Report retrieval talks to /dev/csv-guest through ioctl. It is implemented for
// linux and fails closed with ErrUnsupported everywhere else.
package csvattest
