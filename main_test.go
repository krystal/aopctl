package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/krystal/aopctl/aopctl"
	"github.com/krystal/aopctl/internal/cftest"
)

type testCA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM string
	keyPEM  string
}

func newTestCA(t *testing.T, days int) *testCA {
	t.Helper()
	cert, key, err := aopctl.CreateCA(aopctl.CARequest{CommonName: "Test AOP CA", KeyType: aopctl.KeyTypeECP256, Days: days})
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	keyPEM, err := aopctl.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("encode CA key: %v", err)
	}
	return &testCA{cert: cert, key: key, certPEM: aopctl.EncodeCertificatePEM(cert), keyPEM: keyPEM}
}

// issue returns the PEM of a leaf signed by the CA.
func (ca *testCA) issue(t *testing.T) string {
	t.Helper()
	return cftest.IssueLeaf(t, ca.cert, ca.key)
}

// harness runs the CLI against a fake Cloudflare with injected terminals,
// clock and waits.
type harness struct {
	t    *testing.T
	fake *cftest.Fake
	srv  *httptest.Server
	ca   *testCA
	env  map[string]string

	stdin     string
	stdoutTTY bool
	stdinTTY  bool
	openTTY   func() (io.ReadWriteCloser, error)
	now       time.Time

	// waits counts poll waits. When waitLimit is set, that wait reports the
	// budget as exhausted. blockWaits makes every wait last until the
	// command's budget runs out, as a poll interval longer than the budget
	// does.
	waits      int
	waitLimit  int
	blockWaits bool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake, srv := cftest.New(t)
	ca := newTestCA(t, 3650)
	return &harness{
		t:    t,
		fake: fake,
		srv:  srv,
		ca:   ca,
		env: map[string]string{
			"CLOUDFLARE_API_TOKEN": cftest.Token,
			"CLOUDFLARE_ZONE_ID":   cftest.Zone,
			"AOP_CA_CERT":          ca.certPEM,
			"AOP_CA_KEY":           ca.keyPEM,
		},
		openTTY: func() (io.ReadWriteCloser, error) {
			return nil, errors.New("no terminal in tests")
		},
	}
}

func (h *harness) run(args ...string) (code int, stdout, stderr string) {
	h.t.Helper()
	var out, errOut bytes.Buffer
	a := &app{
		stdin:            strings.NewReader(h.stdin),
		stdout:           &out,
		stderr:           &errOut,
		getenv:           func(k string) string { return h.env[k] },
		stdoutIsTerminal: func() bool { return h.stdoutTTY },
		stdinIsTerminal:  func() bool { return h.stdinTTY },
		openTTY:          h.openTTY,
		baseURL:          h.srv.URL,
		wait: func(ctx context.Context, _ time.Duration) error {
			h.waits++
			if h.blockWaits {
				<-ctx.Done()
				return ctx.Err()
			}
			if h.waitLimit > 0 && h.waits >= h.waitLimit {
				return context.DeadlineExceeded
			}
			return ctx.Err()
		},
		now: func() time.Time {
			if h.now.IsZero() {
				return time.Now()
			}
			return h.now
		},
	}
	code = a.run(args)
	return code, out.String(), errOut.String()
}

// fakeTTY is a terminal that answers with input and records the prompt.
type fakeTTY struct {
	io.Reader
	prompt bytes.Buffer
}

func (t *fakeTTY) Write(p []byte) (int, error) { return t.prompt.Write(p) }
func (t *fakeTTY) Close() error                { return nil }

func TestUsage(t *testing.T) {
	tests := []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"-h"}, 0},
		{[]string{"help"}, 0},
		{[]string{"hostname", "-h"}, 0},
		{[]string{"hostname", "issue", "-h"}, 0},
		{[]string{"ca"}, 2},
		{[]string{"hostname", "rotate"}, 2},
		{[]string{"hostname", "status", "extra"}, 2},
		{[]string{"hostname", "status", "--bogus"}, 2},
		{[]string{"version", "-h"}, 0},
		{[]string{"version", "extra"}, 2},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			h := newHarness(t)
			code, stdout, stderr := h.run(tt.args...)
			if code != tt.code {
				t.Fatalf("exit %d, want %d; stderr:\n%s", code, tt.code, stderr)
			}
			if !strings.Contains(stderr, "Usage: aopctl") {
				t.Errorf("stderr has no usage:\n%s", stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}

func TestDefaultKeyTypes(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now().Truncate(time.Second)

	code, stdout, stderr := h.run("ca", "create")
	if code != 0 {
		t.Fatalf("ca create: exit %d; stderr:\n%s", code, stderr)
	}
	cert, key := parseItemPair(t, stdout)
	if got := describeKey(key.Public()); got != "ECDSA P-256" {
		t.Errorf("ca create key type = %s, want ECDSA P-256", got)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != 3650*24*time.Hour {
		t.Errorf("ca create validity = %s, want 3650 days", got)
	}

	code, _, stderr = h.run("hostname", "issue", "--dry-run", "--hostname", "app.example.com")
	if code != 0 {
		t.Fatalf("hostname issue: exit %d; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "key type:    ECDSA P-256") {
		t.Errorf("hostname issue plan does not show a P-256 key:\n%s", stderr)
	}
	expires := h.now.UTC().Add(-time.Hour).AddDate(0, 0, 365).Format(time.RFC3339)
	if !strings.Contains(stderr, "expires:     "+expires) {
		t.Errorf("hostname issue plan does not expire after 365 days (%s):\n%s", expires, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	hosts := make([]string, 101)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.com", i)
	}
	type usageTest struct {
		name string
		args []string
		env  string
	}
	tests := []usageTest{
		{"ca key type", []string{"ca", "create", "--key-type", "ed25519"}, ""},
		{"hostname key type", []string{"hostname", "issue", "--key-type", "rsa-2048", "--hostname", "a.example.com"}, ""},
		{"ca days zero", []string{"ca", "create", "--days", "0"}, ""},
		{"hostname days negative", []string{"hostname", "issue", "--days", "-1", "--hostname", "a.example.com"}, ""},
		{"issue timeout zero", []string{"hostname", "issue", "--timeout", "0s", "--hostname", "a.example.com"}, ""},
		{"associate timeout negative", []string{"hostname", "associate", "--cert-id", "x", "--timeout", "-1s", "--hostname", "a.example.com"}, ""},
		{"prune timeout zero", []string{"hostname", "prune", "--cert-id", "x", "--timeout", "0s", "--hostname", "a.example.com"}, ""},
		{"101 hostnames from env", []string{"hostname", "issue", "--dry-run"}, strings.Join(hosts, ",")},
		{"101 hostname flags", append([]string{"hostname", "issue", "--dry-run"}, hostnameArgs(hosts)...), ""},
		{"associate without cert id", []string{"hostname", "associate", "--hostname", "a.example.com"}, ""},
		{"invalid hostname", []string{"hostname", "status", "--hostname", "*.example.com"}, ""},
	}
	for _, id := range []string{".", "..", "a/b", ""} {
		tests = append(tests,
			usageTest{"associate cert id " + strconv.Quote(id), []string{"hostname", "associate", "--cert-id", id, "--hostname", "a.example.com"}, ""},
			usageTest{"prune cert id " + strconv.Quote(id), []string{"hostname", "prune", "--cert-id", id, "--cert-id", "old", "--yes", "--hostname", "a.example.com"}, ""},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.env["AOP_HOSTNAMES"] = tt.env
			code, stdout, stderr := h.run(tt.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if n := len(h.fake.Recorded()); n != 0 {
				t.Errorf("sent %d requests, want none", n)
			}
		})
	}
}

func TestHundredHostnamesAccepted(t *testing.T) {
	h := newHarness(t)
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.com", i)
	}
	h.env["AOP_HOSTNAMES"] = strings.Join(hosts, " ")
	code, _, stderr := h.run("hostname", "issue", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	if n := h.fake.Count(http.MethodGet, "/hostnames/h99.example.com"); n != 1 {
		t.Errorf("read the 100th hostname %d times, want 1", n)
	}
}

func hostnameArgs(hosts []string) []string {
	var args []string
	for _, h := range hosts {
		args = append(args, "--hostname", h)
	}
	return args
}

func TestHostnames(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		flags []string
		want  []string
		err   bool
	}{
		{
			name: "env normalized",
			env:  " App.Example.COM., b.example.com\nb.example.com\tc.example.com,,",
			want: []string{"app.example.com", "b.example.com", "c.example.com"},
		},
		{
			name:  "flags replace env",
			env:   "a.example.com",
			flags: []string{"X.example.com", " y.example.com. ", "x.example.com"},
			want:  []string{"x.example.com", "y.example.com"},
		},
		{name: "empty", env: " , ", want: nil},
		{name: "wildcard", flags: []string{"*.example.com"}, err: true},
		{name: "port", flags: []string{"a.example.com:443"}, err: true},
		{name: "path", flags: []string{"a.example.com/x"}, err: true},
		{name: "whitespace", flags: []string{"a.example.com b.example.com"}, err: true},
		{name: "wildcard in env", env: "a.example.com,*.example.com", err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{getenv: func(string) string { return tt.env }}
			got, err := a.hostnames(tt.flags)
			if tt.err {
				if _, ok := errors.AsType[*usageError](err); !ok {
					t.Fatalf("err = %v, want a usage error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("hostnames: %v", err)
			}
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("hostnames = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "-version", "--version"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{stdout: &stdout, stderr: &stderr, version: "v1.2.3"}
			if code := a.run([]string{arg}); code != 0 {
				t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr.String())
			}
			if got := stdout.String(); got != "aopctl v1.2.3\n" {
				t.Errorf("stdout = %q, want %q", got, "aopctl v1.2.3\n")
			}
			if stderr.Len() > 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestResolveVersion(t *testing.T) {
	buildInfo := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: "github.com/krystal/aopctl", Version: v}}, true
		}
	}
	tests := []struct {
		name         string
		buildVersion string
		info         func() (*debug.BuildInfo, bool)
		want         string
	}{
		{name: "release build", buildVersion: "v1.2.3", info: buildInfo("v0.0.0-20260101000000-abcdef123456+dirty"), want: "v1.2.3"},
		{name: "go install", info: buildInfo("v1.2.3"), want: "v1.2.3"},
		{name: "source build", info: buildInfo("(devel)"), want: "(devel)"},
		{name: "no build info", info: func() (*debug.BuildInfo, bool) { return nil, false }, want: "(devel)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.buildVersion, tt.info); got != tt.want {
				t.Errorf("resolveVersion = %q, want %q", got, tt.want)
			}
		})
	}
}
