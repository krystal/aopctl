package aopctl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// KeyType names the algorithm and size of a new key.
type KeyType string

// The key types aopctl generates.
const (
	KeyTypeECP256  KeyType = "ec-p256"
	KeyTypeRSA3072 KeyType = "rsa-3072"
)

func generateKey(keyType KeyType) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeECP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case KeyTypeRSA3072:
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, fmt.Errorf("unknown key type %q", keyType)
}

func validateDays(days int) error {
	if days <= 0 {
		return fmt.Errorf("days must be positive, got %d", days)
	}
	return nil
}

// newSerial returns a random, positive 128-bit serial number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// CARequest describes a new CA.
type CARequest struct {
	CommonName string
	KeyType    KeyType
	// Days is the validity in days, counted from an hour before Now.
	Days int
	// Now is the creation time. The zero value means time.Now().
	Now time.Time
}

// CreateCA creates a self-signed, single-tier CA that may only sign leaves.
func CreateCA(req CARequest) (*x509.Certificate, crypto.Signer, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	return createCA(req.CommonName, req.KeyType, req.Days, now)
}

func createCA(cn string, keyType KeyType, days int, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	if err := validateDays(days); err != nil {
		return nil, nil, err
	}
	key, err := generateKey(keyType)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	notBefore := now.UTC().Add(-time.Hour)
	// CreateCertificate derives the SubjectKeyId from the public key for CA
	// templates, and leaves signed by this CA get a matching AuthorityKeyId.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	cert, err := signCert(tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// createLeaf issues an AOP client certificate. It fails before generating
// anything when the CA would expire before the leaf.
func createLeaf(ca *x509.Certificate, caKey crypto.Signer, cn string, keyType KeyType, days int, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	if err := validateDays(days); err != nil {
		return nil, nil, err
	}
	notBefore := now.UTC().Add(-time.Hour)
	notAfter := notBefore.AddDate(0, 0, days)
	if notAfter.After(ca.NotAfter) {
		return nil, nil, &CAExpiryError{CANotAfter: ca.NotAfter, LeafNotAfter: notAfter}
	}
	key, err := generateKey(keyType)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	// Go's TLS server rejects client certificates without the clientAuth EKU.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	cert, err := signCert(tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func signCert(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// verifyLeaf checks the leaf chains to the CA for client authentication.
func verifyLeaf(leaf, ca *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// EncodeCertificatePEM encodes the certificate as a CERTIFICATE PEM block.
func EncodeCertificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// EncodePrivateKeyPEM encodes the key as a PKCS#8 PRIVATE KEY PEM block,
// which Cloudflare accepts for both key types.
func EncodePrivateKeyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// decodePEM returns the first PEM block of the wanted type. Errors never
// include the input, which may be a private key.
func decodePEM(data, blockType string) ([]byte, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(data)))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("want a %s PEM block, got %s", blockType, block.Type)
	}
	return block.Bytes, nil
}

// ParseCertificatePEM parses the first PEM block, which must be a
// certificate. Surrounding whitespace is ignored.
func ParseCertificatePEM(data string) (*x509.Certificate, error) {
	der, err := decodePEM(data, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// ParseCACertificate parses a certificate with ParseCertificatePEM and
// returns ErrNotCA unless it is a CA certificate.
func ParseCACertificate(data string) (*x509.Certificate, error) {
	cert, err := ParseCertificatePEM(data)
	if err != nil {
		return nil, err
	}
	if err := checkCA(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func checkCA(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("no CA certificate")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return ErrNotCA
	}
	return nil
}

// ParsePrivateKeyPEM parses the first PEM block, which must be a PKCS#8
// private key. Errors never include the input.
func ParsePrivateKeyPEM(data string) (crypto.Signer, error) {
	der, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("%w (want PKCS#8)", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return signer, nil
}

func keyMatchesCert(cert *x509.Certificate, key crypto.Signer) bool {
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(cert.PublicKey)
}

// Fingerprint formats the SHA-256 digest of the DER encoding as uppercase,
// colon-separated hex, as openssl x509 -fingerprint -sha256 does.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// CAProfileWarnings lists the ways a certificate differs from the AOP CA
// profile: a CA with pathlen 0, certificate signing, and no EKU.
func CAProfileWarnings(cert *x509.Certificate) []string {
	var warnings []string
	if !cert.BasicConstraintsValid || !cert.IsCA {
		warnings = append(warnings, "not a CA certificate")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		warnings = append(warnings, "key usage does not include certificate signing")
	}
	if len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0 {
		warnings = append(warnings, "has an extended key usage, so it may be used for more than AOP")
	}
	if cert.IsCA && (cert.MaxPathLen != 0 || !cert.MaxPathLenZero) {
		warnings = append(warnings, "path length is not 0, so it may sign intermediate CAs")
	}
	return warnings
}
