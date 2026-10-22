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
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, err, "create CA")
	keyPEM, err := aopctl.EncodePrivateKeyPEM(key)
	require.NoError(t, err, "encode CA key")
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
	return h.runContext(context.Background(), args...)
}

// runContext runs the CLI with ctx as the command's context.
func (h *harness) runContext(ctx context.Context, args ...string) (code int, stdout, stderr string) {
	h.t.Helper()
	cmd := newRootCmd(h.app())
	return h.capture(cmd, func() int { return execute(ctx, cmd, args) })
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

// blockingTTY is a terminal whose reads wait until it is closed. prompted
// is closed once the prompt is written.
type blockingTTY struct {
	prompted   chan struct{}
	closed     chan struct{}
	promptOnce sync.Once
	closeOnce  sync.Once
}

func newBlockingTTY() *blockingTTY {
	return &blockingTTY{prompted: make(chan struct{}), closed: make(chan struct{})}
}

func (t *blockingTTY) Read([]byte) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}

func (t *blockingTTY) Write(p []byte) (int, error) {
	t.promptOnce.Do(func() { close(t.prompted) })
	return len(p), nil
}

func (t *blockingTTY) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

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
		{[]string{"help", "hostname"}, 0, "Usage:\n  aopctl hostname [flags]\n  aopctl hostname [command]", ""},
		{[]string{"help", "hostname", "issue"}, 0, "Usage:\n  aopctl hostname issue [flags]", ""},
		{[]string{"completion"}, 2, "", "Usage:\n  aopctl completion [flags]\n  aopctl completion [command]"},
		{[]string{"completion", "zsh"}, 0, "#compdef aopctl\n", ""},
		{[]string{"completion", "zsh", "--help"}, 0, "Usage:\n  aopctl completion zsh", ""},
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
			require.Equal(t, tt.code, code, "exit code; stderr:\n%s", stderr)
			for _, out := range []struct{ name, got, want string }{{"stdout", stdout, tt.stdout}, {"stderr", stderr, tt.stderr}} {
				if out.want == "" {
					assert.Empty(t, out.got, out.name)
				}
				assert.Contains(t, out.got, out.want, out.name)
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
		{"positional argument", []string{"zone", "status", "extra"}, "aopctl: unexpected argument \"extra\"\nRun 'aopctl zone status --help' for usage.\n"},
		{"unknown command", []string{"rotate"}, "aopctl: unknown command \"rotate\" for \"aopctl\"\nRun 'aopctl --help' for usage.\n"},
		{"unknown subcommand", []string{"hostname", "rotate"}, "aopctl: unknown command \"rotate\" for \"aopctl hostname\"\nRun 'aopctl hostname --help' for usage.\n"},
		{"help for an unknown command", []string{"help", "bogus"}, "aopctl: unknown command \"bogus\" for \"aopctl\"\nRun 'aopctl --help' for usage.\n"},
		{"help for an unknown subcommand", []string{"help", "hostname", "bogus"}, "aopctl: unknown command \"bogus\" for \"aopctl hostname\"\nRun 'aopctl hostname --help' for usage.\n"},
		{"help with an argument", []string{"help", "hostname", "status", "extra"}, "aopctl: unexpected argument \"extra\"\nRun 'aopctl hostname status --help' for usage.\n"},
		{"unknown shell", []string{"completion", "bogus"}, "aopctl: unknown command \"bogus\" for \"aopctl completion\"\nRun 'aopctl completion --help' for usage.\n"},
		{"completion argument", []string{"completion", "zsh", "extra"}, "aopctl: unexpected argument \"extra\"\nRun 'aopctl completion zsh --help' for usage.\n"},
		{"validation", []string{"ca", "create", "--days", "0"}, "aopctl: --days must be positive, got 0\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			code, stdout, stderr := h.run(tt.args...)
			assert.Equal(t, 2, code, "exit code")
			assert.Equal(t, tt.stderr, stderr, "stderr")
			assert.Empty(t, stdout, "stdout")
			assert.Empty(t, h.fake.Recorded(), "requests sent")
		})
	}
}

// TestMissingCommandHelp checks that a group run without a subcommand
// prints to stderr exactly the help that --help prints to stdout.
func TestMissingCommandHelp(t *testing.T) {
	for _, group := range []string{"", "ca", "hostname", "zone", "completion"} {
		t.Run(strings.TrimSpace("aopctl "+group), func(t *testing.T) {
			args := strings.Fields(group)
			h := newHarness(t)
			code, stdout, stderr := h.run(args...)
			assert.Equal(t, 2, code, "exit code")
			assert.Empty(t, stdout, "stdout")
			_, help, _ := h.run(append(args, "--help")...)
			assert.Equal(t, help, stderr, "stderr, want the --help output")
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
			assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "Dry run: nothing changed.")
			assert.Empty(t, h.fake.Writes(), "dry run write requests")
		})
	}
}

func TestHostnameFlagLists(t *testing.T) {
	h := newHarness(t)
	h.env["AOP_HOSTNAMES"] = hostD
	code, _, stderr := h.run("hostname", "issue", "--dry-run", "--hostname", hostA+","+hostB, "--hostname", hostC)
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	want := "Hostnames:\n  " + hostA + ": none -> new\n  " + hostB + ": none -> new\n  " + hostC + ": none -> new\nDry run"
	assert.Contains(t, stderr, want)
}

func TestEmptyHostnameFlag(t *testing.T) {
	// An empty --hostname replaces AOP_HOSTNAMES rather than falling back to
	// it.
	for _, args := range [][]string{
		{"hostname", "issue", "--hostname", ""},
		{"hostname", "associate", "--cert-id", "new-1", "--hostname="},
		{"hostname", "prune", "--cert-id", "old", "--yes", "--hostname", ""},
	} {
		t.Run(args[1], func(t *testing.T) {
			h := newHarness(t)
			h.env["AOP_HOSTNAMES"] = hostA
			code, _, stderr := h.run(args...)
			assert.Equal(t, 1, code, "exit code")
			assert.Equal(t, "aopctl: no hostnames: set AOP_HOSTNAMES or pass --hostname\n", stderr, "stderr")
			assert.Empty(t, h.fake.Recorded(), "requests sent")
		})
	}

	t.Run("status", func(t *testing.T) {
		h := newHarness(t)
		h.env["AOP_HOSTNAMES"] = hostA
		code, stdout, stderr := h.run("hostname", "status", "--hostname", "")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Zero(t, h.fake.Count(http.MethodGet, "/hostnames/"+hostA), "reads of AOP_HOSTNAMES")
		assert.NotContains(t, stdout, "Hostnames:", "reported AOP_HOSTNAMES")
	})
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
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			assert.True(t, strings.HasSuffix(stdout, ":4\n"), "directive is not 4, no file completion:\n%s", stdout)
			assert.Contains(t, stdout, tt.want, "stdout")
			assert.Empty(t, h.fake.Recorded(), "requests sent")
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
		require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		for _, want := range []string{
			"To resume, run:\n  othertool aopctl hostname associate --cert-id new-1 --hostname",
			"To roll back, run:\n  othertool aopctl hostname associate --cert-id old-1 --hostname a.example.com --hostname b.example.com\n",
		} {
			assert.Contains(t, stderr, want)
		}
	})

	t.Run("usage error", func(t *testing.T) {
		h := newHarness(t)
		code, _, stderr := h.runMounted("hostname", "status", "--bogus")
		assert.Equal(t, 2, code, "exit code")
		assert.Equal(t, "aopctl: unknown flag: --bogus\nRun 'othertool aopctl hostname status --help' for usage.\n", stderr, "stderr")
	})

	t.Run("missing command", func(t *testing.T) {
		h := newHarness(t)
		code, stdout, stderr := h.runMounted("hostname")
		assert.Equal(t, 2, code, "exit code")
		// The host prints the error after the help.
		assert.True(t, strings.HasPrefix(stderr, "Manage per-hostname AOP certificates\n\nUsage:\n  othertool aopctl hostname [flags]"),
			"stderr is not the help and the error:\n%s", stderr)
		assert.True(t, strings.HasSuffix(stderr, " for more information about a command.\naopctl: othertool aopctl hostname requires a subcommand\n"),
			"stderr is not the help and the error:\n%s", stderr)
		assert.Empty(t, stdout, "stdout")
	})
}

// TestMountedReuse runs one mounted command tree more than once to check
// that a run leaves no state behind in the commands. Flags still keep their
// values, so hosts build a new tree for each run.
func TestMountedReuse(t *testing.T) {
	h := newHarness(t)
	host := &cobra.Command{Use: "othertool"}
	host.AddCommand(newRootCmd(h.app()))
	run := func(args ...string) (code int, stdout, stderr string) {
		host.SetArgs(append([]string{"aopctl"}, args...))
		return h.capture(host, func() int { return ExitCode(host.Execute()) })
	}

	code, _, _ := run("hostname")
	require.Equal(t, 2, code, "hostname: exit code")
	// capture gives each run new writers.
	code, stdout, stderr := run("hostname", "rotate")
	assert.Equal(t, 2, code, "hostname rotate: exit code")
	assert.Equal(t, "aopctl: unknown command \"rotate\" for \"othertool aopctl hostname\"\nRun 'othertool aopctl hostname --help' for usage.\n", stderr, "hostname rotate: stderr")
	assert.Empty(t, stdout, "hostname rotate: stdout")
	code, stdout, _ = run("hostname", "--help")
	assert.Equal(t, 0, code, "hostname --help: exit code")
	assert.Contains(t, stdout, "Usage:\n  othertool aopctl hostname [flags]", "hostname --help: stdout")
}

// TestContext checks that commands stop when their context is cancelled.
func TestContext(t *testing.T) {
	h := issueHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, stdout, stderr := h.runContext(ctx, "hostname", "issue")
	assert.Equal(t, 1, code, "exit code after the cancellation; stderr:\n%s", stderr)
	assert.Contains(t, stderr, "context canceled")
	assert.Empty(t, stdout, "stdout")
	assert.Empty(t, h.fake.Writes(), "write requests sent")
}

func TestIsTerminal(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "file"))
	require.NoError(t, err)
	defer file.Close()
	for _, tt := range []struct {
		name string
		v    any
	}{
		{"buffer", &bytes.Buffer{}},
		{"reader", strings.NewReader("")},
		{"regular file", file},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, isTerminal(tt.v), "isTerminal")
		})
	}
}

func TestDefaultKeyTypes(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now().Truncate(time.Second)

	code, stdout, stderr := h.run("ca", "create")
	require.Equal(t, 0, code, "ca create: exit code; stderr:\n%s", stderr)
	cert, key := parseItemPair(t, stdout)
	assert.Equal(t, "ECDSA P-256", describeKey(key.Public()), "ca create key type")
	assert.Equal(t, 3650*24*time.Hour, cert.NotAfter.Sub(cert.NotBefore), "ca create validity")

	code, _, stderr = h.run("hostname", "issue", "--dry-run", "--hostname", "app.example.com")
	require.Equal(t, 0, code, "hostname issue: exit code; stderr:\n%s", stderr)
	assert.Contains(t, stderr, "key type:    ECDSA P-256", "hostname issue plan does not show a P-256 key")
	expires := h.now.UTC().Add(-time.Hour).AddDate(0, 0, 365).Format(time.RFC3339)
	assert.Contains(t, stderr, "expires:     "+expires, "hostname issue plan does not expire after 365 days")
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
			require.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
			assert.Empty(t, stdout, "stdout")
			assert.Empty(t, h.fake.Recorded(), "requests sent")
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
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	assert.Equal(t, 1, h.fake.Count(http.MethodGet, "/hostnames/h99.example.com"), "reads of the 100th hostname")
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
		{name: "empty flags replace env", env: "a.example.com", flags: []string{}, want: nil},
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
				var usageErr *usageError
				require.ErrorAs(t, err, &usageErr)
				return
			}
			require.NoError(t, err, "hostnames")
			assert.Equal(t, strings.Join(tt.want, " "), strings.Join(got, " "), "hostnames")
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
			code := execute(context.Background(), cmd, []string{arg})
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr.String())
			assert.Equal(t, "aopctl v1.2.3\n", stdout.String(), "stdout")
			assert.Empty(t, stderr.String(), "stderr")
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
			assert.Equal(t, tt.want, resolveVersion(tt.buildVersion, tt.info), "resolveVersion")
		})
	}
}
