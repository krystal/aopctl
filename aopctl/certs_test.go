package aopctl

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestCA(t *testing.T, days int) *testCA {
	t.Helper()
	cert, key, err := createCA("Test AOP CA", KeyTypeECP256, days, time.Now())
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

func TestLeafProfileAndChain(t *testing.T) {
	ca := newTestCA(t, 3650)
	now := time.Now()
	leaf, key, err := createLeaf(ca.cert, ca.key, "aopctl AOP client", KeyTypeECP256, 365, now)
	if err != nil {
		t.Fatalf("createLeaf: %v", err)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		t.Error("leaf is not CA:FALSE")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %b, want DigitalSignature", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		t.Errorf("EKU = %v %v, want [ClientAuth]", leaf.ExtKeyUsage, leaf.UnknownExtKeyUsage)
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses) != 0 {
		t.Error("leaf has a SAN")
	}
	if !keyMatchesCert(leaf, key) {
		t.Error("leaf key does not match the leaf")
	}
	if err := verifyLeaf(leaf, ca.cert, now); err != nil {
		t.Errorf("client auth verify: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err == nil {
		t.Error("server auth verify passed, want failure")
	}

	rsaLeaf, rsaKey, err := createLeaf(ca.cert, ca.key, "rsa", KeyTypeRSA3072, 30, now)
	if err != nil {
		t.Fatalf("createLeaf rsa: %v", err)
	}
	if k, ok := rsaKey.(*rsa.PrivateKey); !ok || k.N.BitLen() != 3072 {
		t.Errorf("rsa leaf key = %T", rsaKey)
	}
	if err := verifyLeaf(rsaLeaf, ca.cert, now); err != nil {
		t.Errorf("rsa leaf verify: %v", err)
	}
}
