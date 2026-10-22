package cli

import (
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/krystal/aopctl/aopctl"
)

func TestCAProfile(t *testing.T) {
	tests := []struct {
		keyType string
		key     string
	}{
		{string(aopctl.KeyTypeECP256), "ECDSA P-256"},
		{string(aopctl.KeyTypeRSA3072), "RSA 3072"},
	}
	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			h := newHarness(t)
			h.now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			code, stdout, stderr := h.run("ca", "create", "--key-type", tt.keyType, "--days", "100", "--name", "Example AOP CA")
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			cert, key := parseItemPair(t, stdout)

			assert.True(t, cert.BasicConstraintsValid, "not a CA")
			assert.True(t, cert.IsCA, "not a CA")
			assert.Zero(t, cert.MaxPathLen, "MaxPathLen")
			assert.True(t, cert.MaxPathLenZero, "MaxPathLenZero")
			assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, cert.KeyUsage, "KeyUsage")
			assert.Empty(t, cert.ExtKeyUsage, "EKU")
			assert.Empty(t, cert.UnknownExtKeyUsage, "unknown EKU")
			want := h.now.Add(-time.Hour)
			assert.True(t, cert.NotBefore.Equal(want), "NotBefore = %s, want %s", cert.NotBefore, want)
			assert.Equal(t, 100*24*time.Hour, cert.NotAfter.Sub(cert.NotBefore), "validity")
			assert.NotEmpty(t, cert.SubjectKeyId, "SubjectKeyId")
			bits := cert.SerialNumber.BitLen()
			assert.Positive(t, bits, "serial bits")
			assert.LessOrEqual(t, bits, 128, "serial bits")
			assert.Equal(t, "Example AOP CA", cert.Subject.CommonName, "CN")
			assert.Equal(t, tt.key, describeKey(key.Public()), "key")
			assert.Empty(t, aopctl.CAProfileWarnings(cert), "profile warnings")
		})
	}
}

func TestCAShorterThanLeaf(t *testing.T) {
	h := newHarness(t)
	ca := newTestCA(t, 100)
	h.env["AOP_CA_CERT"], h.env["AOP_CA_KEY"] = ca.certPEM, ca.keyPEM
	code, _, stderr := h.run("hostname", "issue", "--hostname", "app.example.com")
	require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
	assert.Contains(t, stderr, "the CA expires", "stderr does not explain the CA expiry")
	assert.Empty(t, h.fake.Recorded(), "requests sent")
}

func TestKeyCertMismatch(t *testing.T) {
	ca, other := newTestCA(t, 3650), newTestCA(t, 3650)
	_, _, err := loadCA(ca.certPEM, other.keyPEM)
	assert.ErrorContains(t, err, "does not match", "loadCA mismatched pair")

	h := newHarness(t)
	h.env["AOP_CA_KEY"] = other.keyPEM
	code, _, stderr := h.run("hostname", "issue", "--dry-run", "--hostname", "app.example.com")
	assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
	assert.Contains(t, stderr, "AOP_CA_KEY does not match")
	assert.Empty(t, h.fake.Recorded(), "requests sent")
}

func TestLoadCARejectsWrongInputs(t *testing.T) {
	ca := newTestCA(t, 3650)
	leafPEM := ca.issue(t)
	_, _, err := loadCA(leafPEM, ca.keyPEM)
	assert.ErrorContains(t, err, "not a CA", "leaf as CA")
	_, _, err = loadCA(ca.certPEM, ca.certPEM)
	assert.ErrorContains(t, err, "PKCS#8", "certificate as key")
}

func TestPEMWhitespace(t *testing.T) {
	h := newHarness(t)
	h.env["AOP_CA_CERT"] = "\n\n  " + h.ca.certPEM + "\n \n"
	h.env["AOP_CA_KEY"] = "\t\n" + h.ca.keyPEM + "\n\n"
	code, _, stderr := h.run("hostname", "issue", "--dry-run", "--hostname", "app.example.com")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	assert.Equal(t, 1, h.fake.Count(http.MethodGet, "/hostnames/app.example.com"), "did not reach the preflight reads")
}
