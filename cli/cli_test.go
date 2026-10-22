package cli

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

	"github.com/spf13/cobra"

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
	cmd := newRootCmd(h.app())
	return h.capture(cmd, func() int { return execute(context.Background(), cmd, args) })
}

// runMounted runs the CLI as the aopctl subcommand of another program,
// which prints errors and maps them to an exit status as cobra programs do.
func (h *harness) runMounted(args ...string) (code int, stdout, stderr string) {
	h.t.Helper()
	host := &cobra.Command{Use: "othertool"}
	host.AddCommand(newRootCmd(h.app()))
	host.SetArgs(append([]string{"aopctl"}, args...))
	return h.capture(host, func() int { return ExitCode(host.Execute()) })
}

// capture runs a command tree with the harness's stdin and returns its
// output.
func (h *harness) capture(cmd *cobra.Command, run func() int) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	cmd.SetIn(strings.NewReader(h.stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	code = run()
	return code, out.String(), errOut.String()
}

func (h *harness) app() *app {
	return &app{
		getenv:           func(k string) string { return h.env[k] },
		stdoutIsTerminal: func(io.Writer) bool { return h.stdoutTTY },
		stdinIsTerminal:  func(io.Reader) bool { return h.stdinTTY },
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
}

// fakeTTY is a terminal that answers with input and records the prompt.
type fakeTTY struct {
	io.Reader
	prompt bytes.Buffer
}

func (t *fakeTTY) Write(p []byte) (int, error) { return t.prompt.Write(p) }
func (t *fakeTTY) Close() error                { return nil }

func TestUsage(t *testing.T) {
	// Help that was asked for goes to stdout. A missing or unknown command
	// prints the help or an error to stderr.
	tests := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{nil, 2, "", "Usage:\n  aopctl [flags]\n  aopctl [command]"},
		{[]string{"-h"}, 0, "Usage:\n  aopctl [flags]\n  aopctl [command]", ""},
		{[]string{"--help"}, 0, "Usage:\n  aopctl [flags]\n  aopctl [command]", ""},
		{[]string{"help"}, 0, "Usage:\n  aopctl [flags]\n  aopctl [command]", ""},
		{[]string{"hostname", "-h"}, 0, "Usage:\n  aopctl hostname [flags]\n  aopctl hostname [command]", ""},
		{[]string{"hostname", "issue", "-h"}, 0, "Usage:\n  aopctl hostname issue [flags]", ""},
		{[]string{"help", "hostname", "issue"}, 0, "Usage:\n  aopctl hostname issue [flags]", ""},
		{[]string{"ca"}, 2, "", "Usage:\n  aopctl ca [flags]\n  aopctl ca [command]"},
		{[]string{"hostname"}, 2, "", "Usage:\n  aopctl hostname [flags]\n  aopctl hostname [command]"},
		{[]string{"hostname", "rotate"}, 2, "", "Run 'aopctl hostname --help' for usage."},
		{[]string{"hostname", "status", "extra"}, 2, "", "Run 'aopctl hostname status --help' for usage."},
		{[]string{"hostname", "status", "--bogus"}, 2, "", "Run 'aopctl hostname status --help' for usage."},
		{[]string{"version", "-h"}, 0, "Usage:\n  aopctl version [flags]", ""},
		{[]string{"version", "extra"}, 2, "", "Run 'aopctl version --help' for usage."},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			h := newHarness(t)
			code, stdout, stderr := h.run(tt.args...)
			if code != tt.code {
				t.Fatalf("exit %d, want %d; stderr:\n%s", code, tt.code, stderr)
			}
			for _, out := range []struct{ name, got, want string }{{"stdout", stdout, tt.stdout}, {"stderr", stderr, tt.stderr}} {
				if out.want == "" && out.got != "" {
					t.Errorf("%s = %q, want empty", out.name, out.got)
				}
				if !strings.Contains(out.got, out.want) {
					t.Errorf("%s lacks %q:\n%s", out.name, out.want, out.got)
				}
			}
		})
	}
}

// TestCommandLineErrors covers each kind of usage error: the message, the
// pointer to the help and exit status 2.
func TestCommandLineErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		stderr string
	}{
		{"unknown flag", []string{"hostname", "status", "--bogus"}, "aopctl: unknown flag: --bogus\nRun 'aopctl hostname status --help' for usage.\n"},
		{"single-dash long flag", []string{"zone", "status", "-help"}, "aopctl: unknown shorthand flag: 'e' in -elp\nRun 'aopctl zone status --help' for usage.\n"},
		{"missing flag value", []string{"zone", "prune", "--cert-id"}, "aopctl: flag needs an argument: --cert-id\nRun 'aopctl zone prune --help' for usage.\n"},
		{"positional argument", []string{"zone", "status", "extra"}, "aopctl: unknown command \"extra\" for \"aopctl zone status\"\nRun 'aopctl zone status --help' for usage.\n"},
		{"unknown command", []string{"rotate"}, "aopctl: unknown command \"rotate\" for \"aopctl\"\nRun 'aopctl --help' for usage.\n"},
		{"unknown subcommand", []string{"hostname", "rotate"}, "aopctl: unknown command \"rotate\" for \"aopctl hostname\"\nRun 'aopctl hostname --help' for usage.\n"},
		{"validation", []string{"ca", "create", "--days", "0"}, "aopctl: --days must be positive, got 0\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			code, stdout, stderr := h.run(tt.args...)
			if code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
			if stderr != tt.stderr {
				t.Errorf("stderr = %q, want %q", stderr, tt.stderr)
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

func TestDryRunShorthand(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) *harness
		args  []string
	}{
		{"hostname issue", newHarness, []string{"hostname", "issue", "-n", "--hostname", hostA}},
		{"hostname associate", func(t *testing.T) *harness {
			h := newHarness(t)
			h.fake.AddCert("new-1", h.ca.issue(t))
			return h
		}, []string{"hostname", "associate", "-n", "--cert-id", "new-1", "--hostname", hostA}},
		{"zone issue", zoneHarness, []string{"zone", "issue", "-n"}},
		{"zone enable", func(t *testing.T) *harness {
			h := zoneHarness(t)
			h.fake.ZoneEnabled = false
			return h
		}, []string{"zone", "enable", "-n"}},
		{"zone prune", func(t *testing.T) *harness {
			h := zoneHarness(t)
			h.fake.ZoneEnabled = false
			return h
		}, []string{"zone", "prune", "-n", "--cert-id", zoneOld}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.setup(t)
			noPrompt(t, h)
			code, _, stderr := h.run(tt.args...)
			if code != 0 || !strings.Contains(stderr, "Dry run: nothing changed.") {
				t.Errorf("exit %d; stderr:\n%s", code, stderr)
			}
			if w := h.fake.Writes(); len(w) != 0 {
				t.Errorf("dry run sent %d write requests", len(w))
			}
		})
	}
}

func TestHostnameFlagLists(t *testing.T) {
	h := newHarness(t)
	h.env["AOP_HOSTNAMES"] = hostD
	code, _, stderr := h.run("hostname", "issue", "--dry-run", "--hostname", hostA+","+hostB, "--hostname", hostC)
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	want := "Hostnames:\n  " + hostA + ": none -> new\n  " + hostB + ": none -> new\n  " + hostC + ": none -> new\nDry run"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr lacks %q:\n%s", want, stderr)
	}
}

// TestCompletion drives cobra's hidden completion command, which prints the
// choices and then the directive, where 4 means no file completion.
func TestCompletion(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"key type", []string{"hostname", "issue", "--key-type", ""}, "ec-p256\nrsa-3072\n:4\n"},
		{"hostnames from AOP_HOSTNAMES", []string{"hostname", "prune", "--hostname", ""}, hostA + "\n" + hostB + "\n" + hostC + "\n:4\n"},
		{"flag value without choices", []string{"ca", "create", "--name", ""}, ":4\n"},
		{"argument", []string{"zone", "status", ""}, ":4\n"},
		{"subcommands", []string{"zone", ""}, "enable\tTurn on zone-level AOP\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.env["AOP_HOSTNAMES"] = hostA + ", " + hostB + "\n" + hostC
			code, stdout, stderr := h.run(append([]string{"__complete"}, tt.args...)...)
			if code != 0 {
				t.Fatalf("exit %d; stderr:\n%s", code, stderr)
			}
			if !strings.HasSuffix(stdout, ":4\n") {
				t.Errorf("directive is not 4, no file completion:\n%s", stdout)
			}
			if !strings.Contains(stdout, tt.want) {
				t.Errorf("stdout = %q, want %q", stdout, tt.want)
			}
			if n := len(h.fake.Recorded()); n != 0 {
				t.Errorf("sent %d requests, want none", n)
			}
		})
	}
}

// TestMounted runs aopctl as a subcommand of another program.
func TestMounted(t *testing.T) {
	t.Run("hints", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPut {
				return false
			}
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		code, _, stderr := h.runMounted("hostname", "issue")
		if code != 1 {
			t.Fatalf("exit %d, want 1; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"To resume, run:\n  othertool aopctl hostname associate --cert-id new-1 --hostname",
			"To roll back, run:\n  othertool aopctl hostname associate --cert-id old-1 --hostname a.example.com --hostname b.example.com\n",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
		}
	})

	t.Run("usage error", func(t *testing.T) {
		h := newHarness(t)
		code, _, stderr := h.runMounted("hostname", "status", "--bogus")
		if code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
		if want := "aopctl: unknown flag: --bogus\nRun 'othertool aopctl hostname status --help' for usage.\n"; stderr != want {
			t.Errorf("stderr = %q, want %q", stderr, want)
		}
	})

	t.Run("missing command", func(t *testing.T) {
		h := newHarness(t)
		code, stdout, stderr := h.runMounted("hostname")
		if code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
		if !strings.HasPrefix(stderr, "Manage per-hostname AOP certificates\n\nUsage:\n  othertool aopctl hostname [flags]") || strings.Contains(stderr, "aopctl:") {
			t.Errorf("stderr is not only the help:\n%s", stderr)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
	})
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
	for _, arg := range []string{"version", "--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := newRootCmd(&app{version: "v1.2.3"})
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			if code := execute(context.Background(), cmd, []string{arg}); code != 0 {
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
	// mounted is the build info of another program that depends on aopctl.
	mounted := func(dep *debug.Module) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			info := &debug.BuildInfo{Main: debug.Module{Path: "example.com/othertool", Version: "v9.9.9"}}
			if dep != nil {
				info.Deps = []*debug.Module{{Path: "example.com/other", Version: "v8.8.8"}, dep}
			}
			return info, true
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
		{name: "mounted", info: mounted(&debug.Module{Path: "github.com/krystal/aopctl", Version: "v1.2.3"}), want: "v1.2.3"},
		{name: "mounted with a local replace", info: mounted(&debug.Module{Path: "github.com/krystal/aopctl", Version: "v1.2.3", Replace: &debug.Module{Path: "../aopctl"}}), want: "(devel)"},
		{name: "mounted without the module", info: mounted(nil), want: "(devel)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.buildVersion, tt.info); got != tt.want {
				t.Errorf("resolveVersion = %q, want %q", got, tt.want)
			}
		})
	}
}
