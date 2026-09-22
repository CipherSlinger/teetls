// Package teetls implements a TEE-TLS / RA-TLS transport that combines ShangMi
// cryptography with Hygon CSV remote attestation.
//
// A connection is an ordinary net.Conn on top of a custom, teetls-only wire
// protocol that borrows TLS 1.3 framing: SM2 for key agreement and certificate
// signatures, SM3 for the transcript, HMAC, HKDF and public-key binding, and
// SM4-GCM for record protection. It is not wire-compatible with RFC 8446 or
// RFC 8998 peers.
//
// The identity key is not a hardware key. Each endpoint generates an ephemeral
// SM2 key pair, has the CSV hardware sign a report over it, and carries that
// report in an X.509 extension (OID 1.3.6.1.4.1.58270.1.1). The peer checks:
//
//   - the PEK signature over the report,
//   - the Hygon chain, anchored at a locally configured HRK,
//   - the binding report USER_DATA[:32] == SM3(certificate public key),
//   - the enclave measurement against Config.ExpectedMeasurements.
//
// Verification is offline and fail-closed. A trust anchor must be supplied
// locally through Config.TrustedHRKCert, Config.HRKCertPath or Config.CertDir;
// material sent by the peer is never treated as an anchor.
//
// Typical use is Dial, Listen or NewHTTPClient.
package teetls
