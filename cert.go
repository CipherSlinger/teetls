package teetls

import (
	"crypto/rand"
	cx509 "crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	gx509 "github.com/tjfoc/gmsm/x509"

	taacrypto "taa/pkg/crypto"
)

// ComputePublicKeySM3 computes the SM3 digest of a DER-encoded public key.
func ComputePublicKeySM3(pubKeyDER []byte) [32]byte {
	return taacrypto.SM3Sum(pubKeyDER)
}

// ParseCertificatePEM parses a PEM-encoded certificate into a standard *cx509.Certificate.
func ParseCertificatePEM(certPEM []byte) (*cx509.Certificate, error) {
	gCert, err := gx509.ReadCertificateFromPem(certPEM)
	if err != nil {
		return nil, fmt.Errorf("read certificate from pem: %w", err)
	}
	return gCert.ToX509Certificate(), nil
}

// GenerateSM2CertificateWithEvidence generates an ephemeral SM2 keypair, obtains CSV attestation
// evidence binding the SM3 digest of the SM2 public key, and returns the PEM-encoded certificate
// and private key.
func GenerateSM2CertificateWithEvidence(provider EvidenceProvider) (certPEM []byte, keyPEM []byte, err error) {
	if provider == nil {
		return nil, nil, errors.New("nil evidence provider")
	}

	// 1. Generate SM2 keypair
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate sm2 key: %w", err)
	}

	// 2. Marshal public key to DER (SubjectPublicKeyInfo)
	pubDER, err := gx509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal sm2 public key: %w", err)
	}

	// 3. Compute SM3 digest of public key DER
	pubDigest := ComputePublicKeySM3(pubDER)

	// 4. Retrieve attestation evidence from provider
	evidence, err := provider.GetEvidence(pubDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("get attestation evidence: %w", err)
	}

	// 5. Encode evidence into X.509 extension
	ext, err := EncodeCSVEvidence(evidence)
	if err != nil {
		return nil, nil, fmt.Errorf("encode csv evidence extension: %w", err)
	}

	// 6. Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &gx509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "TEE-TLS Ephemeral SM2 Certificate",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              gx509.KeyUsageDigitalSignature | gx509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []gx509.ExtKeyUsage{gx509.ExtKeyUsageServerAuth, gx509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       []pkix.Extension{ext},
	}

	// 7. Self-sign certificate using SM2 private key
	certPEM, err = gx509.CreateCertificateToPem(template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate pem: %w", err)
	}

	// 8. Marshal private key to PEM
	keyPEM, err = gx509.WritePrivateKeyToPem(priv, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal sm2 private key pem: %w", err)
	}

	return certPEM, keyPEM, nil
}
