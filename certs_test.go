package main

import (
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

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
			if code != 0 {
				t.Fatalf("exit %d; stderr:\n%s", code, stderr)
			}
			cert, key := parseItemPair(t, stdout)

			if !cert.BasicConstraintsValid || !cert.IsCA {
				t.Error("not a CA")
			}
			if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
				t.Errorf("MaxPathLen = %d (zero %v), want 0", cert.MaxPathLen, cert.MaxPathLenZero)
			}
			if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
				t.Errorf("KeyUsage = %b, want CertSign|CRLSign", cert.KeyUsage)
			}
			if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
				t.Errorf("has EKU %v %v", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
			}
			if want := h.now.Add(-time.Hour); !cert.NotBefore.Equal(want) {
				t.Errorf("NotBefore = %s, want %s", cert.NotBefore, want)
			}
			if got := cert.NotAfter.Sub(cert.NotBefore); got != 100*24*time.Hour {
				t.Errorf("validity = %s, want 100 days", got)
			}
			if len(cert.SubjectKeyId) == 0 {
				t.Error("no SubjectKeyId")
			}
			if bits := cert.SerialNumber.BitLen(); bits == 0 || bits > 128 {
				t.Errorf("serial has %d bits, want 1 to 128", bits)
			}
			if cert.Subject.CommonName != "Example AOP CA" {
				t.Errorf("CN = %q", cert.Subject.CommonName)
			}
			if got := describeKey(key.Public()); got != tt.key {
				t.Errorf("key = %s, want %s", got, tt.key)
			}
			if warnings := aopctl.CAProfileWarnings(cert); len(warnings) != 0 {
				t.Errorf("profile warnings: %v", warnings)
			}
		})
	}
}

func TestCAShorterThanLeaf(t *testing.T) {
	h := newHarness(t)
	ca := newTestCA(t, 100)
	h.env["AOP_CA_CERT"], h.env["AOP_CA_KEY"] = ca.certPEM, ca.keyPEM
	code, _, stderr := h.run("hostname", "issue", "--hostname", "app.example.com")
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "the CA expires") {
		t.Errorf("stderr does not explain the CA expiry:\n%s", stderr)
	}
	if n := len(h.fake.Recorded()); n != 0 {
		t.Errorf("sent %d requests, want none", n)
	}
}

func TestKeyCertMismatch(t *testing.T) {
	ca, other := newTestCA(t, 3650), newTestCA(t, 3650)
	if _, _, err := loadCA(ca.certPEM, other.keyPEM); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("loadCA mismatched pair: err = %v", err)
	}

	h := newHarness(t)
	h.env["AOP_CA_KEY"] = other.keyPEM
	code, _, stderr := h.run("hostname", "issue", "--dry-run", "--hostname", "app.example.com")
	if code != 1 || !strings.Contains(stderr, "AOP_CA_KEY does not match") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
	if n := len(h.fake.Recorded()); n != 0 {
		t.Errorf("sent %d requests, want none", n)
	}
}

func TestLoadCARejectsWrongInputs(t *testing.T) {
	ca := newTestCA(t, 3650)
	leafPEM := ca.issue(t)
	if _, _, err := loadCA(leafPEM, ca.keyPEM); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("leaf as CA: err = %v", err)
	}
	if _, _, err := loadCA(ca.certPEM, ca.certPEM); err == nil || !strings.Contains(err.Error(), "PKCS#8") {
		t.Errorf("certificate as key: err = %v", err)
	}
}

func TestPEMWhitespace(t *testing.T) {
	h := newHarness(t)
	h.env["AOP_CA_CERT"] = "\n\n  " + h.ca.certPEM + "\n \n"
	h.env["AOP_CA_KEY"] = "\t\n" + h.ca.keyPEM + "\n\n"
	code, _, stderr := h.run("hostname", "issue", "--dry-run", "--hostname", "app.example.com")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	if n := h.fake.Count(http.MethodGet, "/hostnames/app.example.com"); n != 1 {
		t.Errorf("did not reach the preflight reads")
	}
}
