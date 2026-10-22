package cli

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/krystal/aopctl/aopctl"
)

// vectorCA is a fixed CA certificate. vectorFingerprint is the output of
// openssl x509 -noout -fingerprint -sha256 for it.
const (
	vectorCA = `-----BEGIN CERTIFICATE-----
MIIBZzCCAQ2gAwIBAgICEJIwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAxMORXhhbXBs
ZSBBT1AgQ0EwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAZMRcwFQYD
VQQDEw5FeGFtcGxlIEFPUCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNF9
uJ/vO3AjYkdwnGeN/e2eZHbQ04hskneAPlA3pFbTCQSfSRJAEHcphhBOXHURx45t
L5pMOGMUJyK73OoHVkWjRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQRqXOckKyZf4vQA4jLr2QKuCGlWzAKBggqhkjOPQQD
AgNIADBFAiEAo9ur3VGscrbX4wny93dFNOzr8AA4aP5WbTkwXV3LWe8CIDlU6455
ohfFPfilIEcPyzQMDZf1NYmtbBSFzvYheKLC
-----END CERTIFICATE-----
`
	vectorFingerprint = "6D:C4:0A:FB:5F:13:28:70:E4:47:04:AE:A7:3C:8E:66:F2:B4:63:A3:07:B2:D2:68:30:12:09:9B:77:AD:AB:DF"
)

type itemField struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
	Label   string `json:"label"`
	Value   string `json:"value"`
}

type item struct {
	Title    string      `json:"title"`
	Category string      `json:"category"`
	Fields   []itemField `json:"fields"`
}

func parseItem(t *testing.T, stdout string) (item, map[string]itemField) {
	t.Helper()
	var it item
	require.NoError(t, json.Unmarshal([]byte(stdout), &it), "stdout is not JSON")
	fields := map[string]itemField{}
	for _, f := range it.Fields {
		fields[f.ID] = f
	}
	return it, fields
}

// parseItemPair returns the CA pair from a ca create item template, checking
// that the key matches the certificate.
func parseItemPair(t *testing.T, stdout string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	_, fields := parseItem(t, stdout)
	cert, key, err := loadCA(fields["ca_cert"].Value, fields["ca_key"].Value)
	require.NoError(t, err, "item template pair")
	return cert, key
}

func TestCACreateRefusesTerminal(t *testing.T) {
	h := newHarness(t)
	h.stdoutTTY = true
	code, stdout, stderr := h.run("ca", "create")
	require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
	assert.Empty(t, stdout, "wrote to the terminal")
	assert.Contains(t, stderr, "op item create", "stderr does not explain how to pipe the output")
}

func TestCACreateOutput(t *testing.T) {
	h := newHarness(t)
	code, stdout, stderr := h.run("ca", "create", "--name", "Example AOP CA")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	it, fields := parseItem(t, stdout)
	assert.Equal(t, "SECURE_NOTE", it.Category, "category")
	assert.Equal(t, "Example AOP CA", it.Title, "title")
	wantTypes := map[string]string{
		"ca_cert":            "STRING",
		"ca_key":             "CONCEALED",
		"fingerprint_sha256": "STRING",
		"notesPlain":         "STRING",
	}
	for id, typ := range wantTypes {
		if f, ok := fields[id]; assert.True(t, ok, "field %s is missing", id) {
			assert.Equal(t, typ, f.Type, "field %s type", id)
			assert.Equal(t, id, f.Label, "field %s label", id)
		}
	}
	assert.Equal(t, "NOTES", fields["notesPlain"].Purpose, "notesPlain purpose")
	assert.Contains(t, fields["notesPlain"].Value, "Expires", "notesPlain value")

	cert, _ := parseItemPair(t, stdout)
	fp := aopctl.Fingerprint(cert)
	assert.Equal(t, fp, fields["fingerprint_sha256"].Value, "fingerprint field")
	assert.Contains(t, stderr, fp, "stderr does not show the fingerprint")
	assert.NotContains(t, stderr, "PRIVATE KEY", "stderr contains the key")

	code, stdout, stderr = h.run("ca", "create", "--name", "Example AOP CA", "--title", "Example item")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	it, _ = parseItem(t, stdout)
	assert.Equal(t, "Example item", it.Title, "title, want the --title value")
}

func TestCAShow(t *testing.T) {
	t.Run("details", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = "\n  " + vectorCA + "\n\n"
		code, stdout, stderr := h.run("ca", "show")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		for _, want := range []string{
			"Fingerprint: " + vectorFingerprint,
			"Subject:     CN=Example AOP CA",
			"Not before:  2026-01-01T00:00:00Z",
			"Not after:   2036-01-01T00:00:00Z",
			"Key type:    ECDSA P-256",
		} {
			assert.Contains(t, stdout, want)
		}
		assert.NotContains(t, stdout, "Warning", "unexpected warning")
	})

	t.Run("secret", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = vectorCA
		code, stdout, stderr := h.run("ca", "show", "--secret", "cloudflare-aop-ca", "--namespace", "app")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		header := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: cloudflare-aop-ca\n  namespace: app\ntype: Opaque\nstringData:\n  ca.crt: |\n"
		body, ok := strings.CutPrefix(stdout, header)
		require.True(t, ok, "manifest header mismatch:\n%s", stdout)
		var pemLines []string
		for line := range strings.SplitSeq(strings.TrimRight(body, "\n"), "\n") {
			pemLines = append(pemLines, strings.TrimPrefix(line, "    "))
		}
		cert, err := aopctl.ParseCertificatePEM(strings.Join(pemLines, "\n"))
		require.NoError(t, err, "manifest certificate")
		assert.Equal(t, vectorFingerprint, aopctl.Fingerprint(cert), "manifest holds a different certificate")
	})

	t.Run("profile warning", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = h.ca.issue(t)
		code, stdout, stderr := h.run("ca", "show")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		for _, want := range []string{"Warning:     not a CA certificate", "Warning:     has an extended key usage"} {
			assert.Contains(t, stdout, want)
		}
	})

	t.Run("terminal stdin", func(t *testing.T) {
		h := newHarness(t)
		h.stdinTTY = true
		code, _, stderr := h.run("ca", "show")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "stdin")
	})

	t.Run("namespace without secret", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = vectorCA
		code, _, _ := h.run("ca", "show", "--namespace", "app")
		assert.Equal(t, 2, code, "exit code")
	})
}
