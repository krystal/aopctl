package aopctl

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestCA(t *testing.T, days int) *testCA {
	t.Helper()
	cert, key, err := createCA("Test AOP CA", KeyTypeECP256, days, time.Now())
	require.NoError(t, err, "create CA")
	return &testCA{cert: cert, key: key}
}

func TestLeafProfileAndChain(t *testing.T) {
	ca := newTestCA(t, 3650)
	now := time.Now()
	leaf, key, err := createLeaf(ca.cert, ca.key, "aopctl AOP client", KeyTypeECP256, 365, now)
	require.NoError(t, err, "createLeaf")
	assert.True(t, leaf.BasicConstraintsValid, "leaf is not CA:FALSE")
	assert.False(t, leaf.IsCA, "leaf is not CA:FALSE")
	assert.Equal(t, x509.KeyUsageDigitalSignature, leaf.KeyUsage, "KeyUsage")
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, leaf.ExtKeyUsage, "EKU")
	assert.Empty(t, leaf.UnknownExtKeyUsage, "unknown EKU")
	assert.Zero(t, len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses), "leaf has a SAN")
	assert.True(t, keyMatchesCert(leaf, key), "leaf key does not match the leaf")
	assert.NoError(t, verifyLeaf(leaf, ca.cert, now), "client auth verify")
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	assert.Error(t, err, "server auth verify passed")

	rsaLeaf, rsaKey, err := createLeaf(ca.cert, ca.key, "rsa", KeyTypeRSA3072, 30, now)
	require.NoError(t, err, "createLeaf rsa")
	if k, ok := rsaKey.(*rsa.PrivateKey); assert.True(t, ok, "rsa leaf key = %T", rsaKey) {
		assert.Equal(t, 3072, k.N.BitLen(), "rsa leaf key bits")
	}
	assert.NoError(t, verifyLeaf(rsaLeaf, ca.cert, now), "rsa leaf verify")
}
