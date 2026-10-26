package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/krystal/aopctl/internal/cftest"
)

const (
	refCert  = "op://vault/aop/ca_cert"
	refKey   = "op://vault/aop/ca_key"
	refToken = "op://vault/cloudflare/credential" //nolint:gosec // a reference, not a credential
	refZone  = "op://vault/cloudflare/zone"
)

// writeConfig writes a config file only its owner can read and returns its
// path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600), "write config")
	return path
}

// profileConfig is a config file whose prod profile holds references to the
// harness's CA and the fake's token and zone, and lists hostA and hostB.
var profileConfig = `cloudflare_api_token: ` + refToken + `
profiles:
  prod:
    ca_cert: ` + refCert + `
    ca_key: ` + refKey + `
    cloudflare_zone_id: ` + cftest.Zone + `
    hostnames: [` + hostA + `, ` + hostB + `]
  staging:
    ca_cert: op://vault/staging/ca_cert
`

// configHarness runs the CLI with the config file content, through
// AOPCTL_CONFIG, and an environment of decoys that a config file in use
// must override.
func configHarness(t *testing.T, content string) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	path := writeConfig(t, content)
	other := newTestCA(t, 3650)
	h.env = map[string]string{
		"AOPCTL_CONFIG":      path,
		"AOP_CA_CERT":        other.certPEM,
		"AOP_CA_KEY":         other.keyPEM,
		"CLOUDFLARE_ZONE_ID": "ffffffffffffffffffffffffffffffff",
		"AOP_HOSTNAMES":      hostD,
	}
	h.secrets = map[string]string{
		refCert:  h.ca.certPEM,
		refKey:   h.ca.keyPEM,
		refToken: cftest.Token,
		refZone:  cftest.Zone,
	}
	return h, path
}

// configApp returns an app with aopctl's flags, parsed from args, that reads
// env.
func configApp(t *testing.T, env map[string]string, args ...string) *app {
	t.Helper()
	a := &app{getenv: func(k string) string { return env[k] }}
	cmd := newRootCmd(a)
	require.NoError(t, cmd.PersistentFlags().Parse(args), "parse flags")
	return a
}

func TestConfigFile(t *testing.T) {
	t.Run("hostname status reads only what it needs", func(t *testing.T) {
		h, _ := configHarness(t, profileConfig)
		h.fake.AddCert("old-1", h.ca.issue(t))
		h.fake.SetAssoc(hostA, "old-1", new(true))
		code, stdout, stderr := h.run("--profile", "prod", "hostname", "status")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, []string{refToken, refCert}, h.resolved, "references read")
		assert.Contains(t, stdout, "    signed by ca_cert: yes\n")
		assert.Contains(t, stdout, "  "+hostA+": old-1")
		assert.NotContains(t, stdout, hostD, "hostnames from AOP_HOSTNAMES")
		for _, r := range h.fake.Recorded() {
			assert.Contains(t, r.Path, "/zones/"+cftest.Zone+"/", "request outside the configured zone")
		}
		assert.Empty(t, stderr, "stderr")
	})

	t.Run("printed commands carry the config flags and run as printed", func(t *testing.T) {
		h, path := configHarness(t, profileConfig)
		delete(h.env, "AOPCTL_CONFIG")
		h.fake.AddCert("old-1", h.ca.issue(t))
		h.fake.SetAssoc(hostA, "old-1", new(true))
		h.fake.SetAssoc(hostB, "old-1", new(true))
		code, stdout, stderr := h.run("--config", path, "--profile", "prod", "hostname", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		prefix := "aopctl --config " + path + " --profile prod hostname prune" + zoneOpt + " --cert-id old-1"
		var prune string
		for line := range strings.SplitSeq(stdout, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				prune = strings.TrimSpace(line)
			}
		}
		require.NotEmpty(t, prune, "no prune command starting %q in stdout:\n%s", prefix, stdout)

		code, _, stderr = h.run(append(strings.Fields(prune)[1:], "--yes")...)
		require.Equal(t, 0, code, "exit code of %q; stderr:\n%s", prune, stderr)
		assert.Contains(t, stderr, "Deleted old-1")
	})

	t.Run("a failed read sends no request", func(t *testing.T) {
		h, _ := configHarness(t, profileConfig)
		h.resolveErr = errors.New("not signed in")
		code, _, stderr := h.run("--profile", "prod", "hostname", "issue")
		assert.Equal(t, 1, code, "exit code")
		assert.Equal(t, "aopctl: resolve cloudflare_api_token ("+refToken+"): not signed in\n", stderr, "stderr")
		assert.Empty(t, h.fake.Recorded(), "requests sent")
	})

	t.Run("references are read outside the timeout budget", func(t *testing.T) {
		h, _ := configHarness(t, strings.Replace(profileConfig, cftest.Zone, refZone, 1))
		code, _, stderr := h.run("--profile", "prod", "hostname", "issue", "--dry-run", "--timeout", "1m")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, []string{refToken, refCert, refKey, refZone}, h.resolved, "references read")
		assert.False(t, h.resolvedInBudget, "read a reference within --timeout")
	})

	t.Run("zone reference", func(t *testing.T) {
		for _, args := range [][]string{{"hostname", "status"}, {"zone", "status"}} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				h, _ := configHarness(t, strings.Replace(profileConfig, cftest.Zone, refZone, 1))
				code, _, stderr := h.run(append([]string{"--profile", "prod"}, args...)...)
				require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
				assert.Equal(t, 1, countRef(h.resolved, refZone), "reads of the zone reference")
				require.NotEmpty(t, h.fake.Recorded(), "requests sent")
				for _, r := range h.fake.Recorded() {
					assert.Contains(t, r.Path, "/zones/"+cftest.Zone+"/", "request outside the configured zone")
				}
			})
		}
	})

	t.Run("--zone takes precedence over a zone reference", func(t *testing.T) {
		for _, args := range [][]string{
			{"zone", "status", "--zone", cftest.Zone},
			{"zone", "status", "--zone", cftest.ZoneName},
			{"hostname", "status", "--zone", cftest.Zone},
		} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				h, _ := configHarness(t, strings.Replace(profileConfig, cftest.Zone, refZone, 1))
				delete(h.secrets, refZone)
				code, _, stderr := h.run(append([]string{"--profile", "prod"}, args...)...)
				require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
				assert.Zero(t, countRef(h.resolved, refZone), "reads of the zone reference")
			})
		}
	})

	t.Run("missing --cert-id reads nothing", func(t *testing.T) {
		for _, args := range [][]string{{"hostname", "prune"}, {"zone", "prune"}} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				h, _ := configHarness(t, strings.Replace(profileConfig, cftest.Zone, refZone, 1))
				code, _, stderr := h.run(append([]string{"--profile", "prod"}, args...)...)
				assert.Equal(t, 2, code, "exit code")
				assert.Contains(t, stderr, "aopctl --profile prod "+strings.Join(args[:1], "")+" status to find", "stderr")
				assert.NotContains(t, stderr, "op://", "stderr")
				assert.Empty(t, h.resolved, "references read")
			})
		}
	})

	t.Run("token", func(t *testing.T) {
		withoutToken := strings.Replace(profileConfig, "cloudflare_api_token: "+refToken+"\n", "", 1)
		t.Run("profile overrides the top level", func(t *testing.T) {
			content := strings.Replace(profileConfig, "  prod:\n", "  prod:\n    cloudflare_api_token: op://vault/prod/credential\n", 1)
			h, _ := configHarness(t, content)
			h.secrets["op://vault/prod/credential"] = cftest.Token
			h.secrets[refToken] = "the top-level token"
			code, _, stderr := h.run("--profile", "prod", "hostname", "status")
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			assert.NotContains(t, h.resolved, refToken, "read the top-level token")
		})
		t.Run("environment fallback", func(t *testing.T) {
			h, path := configHarness(t, withoutToken)
			h.env["CLOUDFLARE_API_TOKEN"] = cftest.Token
			code, _, stderr := h.run("--profile", "prod", "hostname", "status")
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			assert.Equal(t, "Note: profile prod of "+path+" sets no cloudflare_api_token, so aopctl uses CLOUDFLARE_API_TOKEN from the environment.\n", stderr, "stderr")
		})
		t.Run("not set", func(t *testing.T) {
			h, path := configHarness(t, withoutToken)
			code, _, stderr := h.run("--profile", "prod", "hostname", "status")
			assert.Equal(t, 1, code, "exit code")
			assert.Equal(t, "aopctl: cloudflare_api_token is not set in profile prod of "+path+", and CLOUDFLARE_API_TOKEN is not set\n", stderr, "stderr")
		})
	})

	t.Run("messages name config file keys", func(t *testing.T) {
		other := newTestCA(t, 3650)
		tests := []struct {
			name    string
			content string
			setup   func(h *harness)
			args    []string
			want    string
		}{
			{"key mismatch", profileConfig, func(h *harness) { h.secrets[refKey] = other.keyPEM }, []string{"hostname", "issue"}, "aopctl: ca_key does not match the certificate in ca_cert\n"},
			{"key not set", strings.Replace(profileConfig, "    ca_key: "+refKey+"\n", "", 1), nil, []string{"hostname", "issue"}, "aopctl: ca_key is not set in profile prod of %s\n"},
			{"no hostnames", strings.Replace(profileConfig, "["+hostA+", "+hostB+"]", "[]", 1), nil, []string{"hostname", "issue"}, "aopctl: no hostnames: set hostnames in profile prod of %s or pass --hostname\n"},
			{"not a CA", profileConfig, func(h *harness) { h.secrets[refCert] = h.ca.issue(t) }, []string{"hostname", "issue"}, "aopctl: ca_cert is not a CA certificate\n"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				h, path := configHarness(t, tt.content)
				if tt.setup != nil {
					tt.setup(h)
				}
				code, _, stderr := h.run(append([]string{"--profile", "prod"}, tt.args...)...)
				assert.Equal(t, 1, code, "exit code")
				want := tt.want
				if strings.Contains(want, "%s") {
					want = fmt.Sprintf(want, path)
				}
				assert.Equal(t, want, stderr, "stderr")
			})
		}
	})

	t.Run("references in the environment", func(t *testing.T) {
		h := newHarness(t)
		h.secrets = map[string]string{refCert: h.ca.certPEM, refKey: h.ca.keyPEM}
		h.env["AOP_CA_CERT"], h.env["AOP_CA_KEY"] = refCert, refKey
		code, _, stderr := h.run("hostname", "issue", "--dry-run", "--hostname", hostA)
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, []string{refCert, refKey}, h.resolved, "references read")
	})

	t.Run("empty value", func(t *testing.T) {
		h, _ := configHarness(t, profileConfig)
		h.secrets[refToken] = " \n"
		code, _, stderr := h.run("--profile", "prod", "hostname", "status")
		assert.Equal(t, 1, code, "exit code")
		assert.Equal(t, "aopctl: cloudflare_api_token: "+refToken+" resolved to an empty value\n", stderr, "stderr")
	})
}

// TestEnvMessages checks the messages that name settings, without a config
// file, exactly as they were before config files.
func TestEnvMessages(t *testing.T) {
	other := newTestCA(t, 3650)
	tests := []struct {
		name  string
		setup func(h *harness)
		args  []string
		want  string
	}{
		{"token not set", func(h *harness) { delete(h.env, "CLOUDFLARE_API_TOKEN") }, []string{"hostname", "status"}, "aopctl: CLOUDFLARE_API_TOKEN is not set\n"},
		{"key not set", func(h *harness) { delete(h.env, "AOP_CA_KEY") }, []string{"hostname", "issue", "--hostname", hostA}, "aopctl: AOP_CA_KEY is not set\n"},
		{"key mismatch", func(h *harness) { h.env["AOP_CA_KEY"] = other.keyPEM }, []string{"hostname", "issue", "--hostname", hostA}, "aopctl: AOP_CA_KEY does not match the certificate in AOP_CA_CERT\n"},
		{"no zone", func(h *harness) { delete(h.env, "CLOUDFLARE_ZONE_ID") }, []string{"zone", "status"}, "aopctl: no zone: pass --zone or set CLOUDFLARE_ZONE_ID\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tt.setup(h)
			code, _, stderr := h.run(tt.args...)
			assert.Equal(t, 1, code, "exit code")
			assert.Equal(t, tt.want, stderr, "stderr")
		})
	}
}

func countRef(refs []string, ref string) int {
	n := 0
	for _, r := range refs {
		if r == ref {
			n++
		}
	}
	return n
}

func TestConfigDiscovery(t *testing.T) {
	flagFile := writeConfig(t, "ca_cert: flag\n")
	envFile := writeConfig(t, "ca_cert: env\n")
	defaultDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(defaultDir, "aopctl"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(defaultDir, "aopctl", "config.yaml"), []byte("ca_cert: default\n"), 0o600))
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	inDir := func(dir string) func() (string, error) { return func() (string, error) { return dir, nil } }

	tests := []struct {
		name      string
		args      []string
		env       map[string]string
		configDir func() (string, error)
		want      string // the config file's ca_cert, or "" for the environment
		err       string
		usage     bool
	}{
		{name: "flag first", args: []string{"--config", flagFile}, env: map[string]string{"AOPCTL_CONFIG": envFile}, configDir: inDir(defaultDir), want: "flag"},
		{name: "then AOPCTL_CONFIG", env: map[string]string{"AOPCTL_CONFIG": envFile}, configDir: inDir(defaultDir), want: "env"},
		{name: "then the default path", configDir: inDir(defaultDir), want: "default"},
		{name: "no default file", configDir: inDir(t.TempDir())},
		{name: "no default path", configDir: func() (string, error) { return "", errors.New("no home") }},
		{name: "default discovery off", env: map[string]string{"AOP_CA_CERT": "from env"}, want: ""},
		{name: "missing --config", args: []string{"--config", missing}, configDir: inDir(defaultDir), err: "config file: open " + missing},
		{name: "missing AOPCTL_CONFIG", env: map[string]string{"AOPCTL_CONFIG": missing}, err: "config file: open " + missing},
		{name: "empty --config", args: []string{"--config", ""}, err: "--config must not be empty", usage: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := configApp(t, tt.env, tt.args...)
			a.configDir = tt.configDir
			c, err := a.config()
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err, "error")
				_, isUsage := errors.AsType[*usageError](err)
				assert.Equal(t, tt.usage, isUsage, "usage error")
				return
			}
			require.NoError(t, err, "config")
			if tt.want == "" {
				assert.Nil(t, c.file, "config file in use")
				return
			}
			require.NotNil(t, c.file, "no config file in use")
			assert.Equal(t, tt.want, c.settings.CACert, "ca_cert")
		})
	}
}

// TestMountedDiscovery checks that a command mounted with Options.Getenv
// reads no default config file, while one reading the process environment
// does.
func TestMountedDiscovery(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "aopctl"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "aopctl", "config.yaml"), []byte("profiles:\n  prod: {}\n"), 0o600))
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("AppData", dir)
	t.Setenv("AOPCTL_CONFIG", "")
	t.Setenv("AOPCTL_PROFILE", "")

	run := func(opts Options) string {
		var stderr bytes.Buffer
		cmd := NewCommand(opts)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&stderr)
		execute(context.Background(), cmd, []string{"hostname", "status"})
		return stderr.String()
	}
	assert.Contains(t, run(Options{}), "no profile: pass --profile", "with the process environment")
	assert.Equal(t, "aopctl: CLOUDFLARE_API_TOKEN is not set\n", run(Options{Getenv: func(string) string { return "" }}), "with Getenv")
}

func TestDefaultConfigDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		dir := t.TempDir()
		t.Setenv("AppData", dir)
		got, err := defaultConfigDir()
		require.NoError(t, err)
		assert.Equal(t, dir, got)
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, tt := range []struct{ xdg, want string }{
		{"/xdg/config", "/xdg/config"},
		{"relative/config", filepath.Join(home, ".config")},
		{"", filepath.Join(home, ".config")},
	} {
		t.Setenv("XDG_CONFIG_HOME", tt.xdg)
		got, err := defaultConfigDir()
		require.NoError(t, err, "XDG_CONFIG_HOME=%q", tt.xdg)
		assert.Equal(t, tt.want, got, "XDG_CONFIG_HOME=%q", tt.xdg)
	}
}

func TestConfigProfiles(t *testing.T) {
	content := `ca_cert: top
ca_key: top
hostnames: [top.example.com]
profiles:
  a:
    ca_cert: a
  b:
    hostnames: []
  c:
    hostnames: [c.example.com]
`
	path := writeConfig(t, content)
	noProfiles := writeConfig(t, "ca_cert: top\n")
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		profile string
		want    fileSettings
		err     string
	}{
		{name: "flag over AOPCTL_PROFILE", args: []string{"--config", path, "--profile", "a"}, env: map[string]string{"AOPCTL_PROFILE": "c"}, profile: "a", want: fileSettings{CACert: "a", CAKey: "top", Hostnames: []string{"top.example.com"}}},
		{name: "AOPCTL_PROFILE", args: []string{"--config", path}, env: map[string]string{"AOPCTL_PROFILE": "c"}, profile: "c", want: fileSettings{CACert: "top", CAKey: "top", Hostnames: []string{"c.example.com"}}},
		{name: "empty hostnames replace the top level", args: []string{"--config", path, "--profile", "b"}, profile: "b", want: fileSettings{CACert: "top", CAKey: "top", Hostnames: []string{}}},
		{name: "no profiles", args: []string{"--config", noProfiles}, want: fileSettings{CACert: "top"}},
		{name: "none selected", args: []string{"--config", path}, err: "no profile: pass --profile or set AOPCTL_PROFILE to one of a, b, c in " + path},
		{name: "unknown", args: []string{"--config", path, "--profile", "d"}, err: `unknown profile "d": want one of a, b, c in ` + path},
		{name: "file without profiles", args: []string{"--config", noProfiles, "--profile", "a"}, err: "profile a: " + noProfiles + " has no profiles"},
		{name: "no config file", env: map[string]string{"AOPCTL_PROFILE": "a"}, err: "profile a needs a config file: pass --config or set AOPCTL_CONFIG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := configApp(t, tt.env, tt.args...).config()
			if tt.err != "" {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error(), "error")
				_, isUsage := errors.AsType[*usageError](err)
				assert.True(t, isUsage, "usage error")
				return
			}
			require.NoError(t, err, "config")
			assert.Equal(t, tt.profile, c.profile, "profile")
			assert.Equal(t, tt.want, c.settings, "settings")
		})
	}
}

func TestConfigDecode(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    fileSettings
		err     string
	}{
		{name: "empty", content: ""},
		{name: "scalars as text", content: "ca_cert: false\nca_key: 123\ncloudflare_zone_id: 01234567890123456789012345678901\nhostnames: [true]\n", want: fileSettings{CACert: "false", CAKey: "123", ZoneID: "01234567890123456789012345678901", Hostnames: []string{"true"}}},
		{name: "unknown key", content: "ca_certs: x\n", err: "field ca_certs not found"},
		{name: "duplicate key", content: "ca_cert: x\nca_cert: y\n", err: `mapping key "ca_cert" already defined`},
		{name: "mapping as a string", content: "ca_cert: {a: b}\n", err: "cannot unmarshal !!map into string"},
		{name: "string as hostnames", content: "hostnames: a.example.com\n", err: "cannot unmarshal !!str `a.examp...` into []string"},
		{name: "second document", content: "ca_cert: x\n---\nca_cert: y\n", err: "want a single YAML document"},
		{name: "invalid profile name", content: "profiles:\n  'a b': {}\n", err: `invalid profile name "a b"`},
		{name: "too large", content: "ca_cert: " + strings.Repeat("x", maxConfigSize) + "\n", err: "is larger than 1048576 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.content)
			c, err := configApp(t, nil, "--config", path).config()
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "config file "+path, "error")
				assert.Contains(t, err.Error(), tt.err, "error")
				return
			}
			require.NoError(t, err, "config")
			assert.Equal(t, tt.want, c.settings, "settings")
		})
	}
}

func TestConfigPermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not say who can read a file")
	}
	literal := "cloudflare_api_token: " + cftest.Token + "\nprofiles:\n  prod:\n    ca_key: literal\n"
	refs := "cloudflare_api_token: " + refToken + "\nca_cert: literal certificate\n"
	tests := []struct {
		content string
		mode    os.FileMode
		warn    bool
	}{
		{literal, 0o644, true},
		{literal, 0o640, true},
		{literal, 0o620, false},
		{literal, 0o600, false},
		{refs, 0o644, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v %04o", tt.warn, tt.mode), func(t *testing.T) {
			h, path := configHarness(t, tt.content)
			require.NoError(t, os.Chmod(path, tt.mode))
			h.env["AOPCTL_PROFILE"] = "prod"
			if tt.content == refs {
				delete(h.env, "AOPCTL_PROFILE")
			}
			_, _, stderr := h.run("hostname", "status")
			warning := "Warning: " + path + " is readable by other users and holds a literal ca_key and cloudflare_api_token: run chmod 600 on it, or use op:// references.\n"
			if tt.warn {
				assert.True(t, strings.HasPrefix(stderr, warning), "stderr:\n%s", stderr)
			} else {
				assert.NotContains(t, stderr, "readable by other users", "stderr")
			}
		})
	}
}

// TestConfigCompletion checks that completion offers what the config file
// holds, reads no secret and prints no config error.
func TestConfigCompletion(t *testing.T) {
	noProfiles := "hostnames: [" + hostA + ", " + hostB + "]\n"
	tests := []struct {
		name    string
		content string
		args    []string
		want    []string
	}{
		{"malformed file, hostnames", "hostnames: [\n", []string{"hostname", "status", "--hostname", ""}, nil},
		{"malformed file, profiles", "hostnames: [\n", []string{"--profile", ""}, nil},
		{"no profile selected, profiles", profileConfig, []string{"--profile", ""}, []string{"prod", "staging"}},
		{"no profile selected, hostnames", profileConfig, []string{"hostname", "status", "--hostname", ""}, nil},
		{"profile selected", profileConfig, []string{"--profile", "prod", "hostname", "status", "--hostname", ""}, []string{hostA, hostB}},
		{"file without profiles", noProfiles, []string{"hostname", "status", "--hostname", ""}, []string{hostA, hostB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := configHarness(t, tt.content)
			code, stdout, stderr := h.run(append([]string{"__complete"}, tt.args...)...)
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
			assert.Equal(t, ":4", lines[len(lines)-1], "directive")
			choices := lines[:len(lines)-1]
			if len(choices) == 0 {
				choices = nil
			}
			assert.Equal(t, tt.want, choices, "choices")
			assert.NotContains(t, stderr, "aopctl", "stderr")
			assert.Empty(t, h.resolved, "references read")
		})
	}
}

// TestConfigMountedHook checks that a host's persistent pre-run hook still
// runs, as aopctl reads its config file in its commands instead.
func TestConfigMountedHook(t *testing.T) {
	h, path := configHarness(t, profileConfig)
	hooked := false
	host := &cobra.Command{Use: "othertool", PersistentPreRunE: func(*cobra.Command, []string) error {
		hooked = true
		return nil
	}}
	host.AddCommand(newRootCmd(h.app()))
	host.SetArgs([]string{"aopctl", "--config", path, "--profile", "prod", "hostname", "status"})
	code, _, stderr := h.capture(host, func() int { return ExitCode(host.Execute()) })
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	assert.True(t, hooked, "host hook ran")
	assert.Equal(t, []string{refToken, refCert}, h.resolved, "references read")
}

func TestCAShowConfig(t *testing.T) {
	t.Run("configured certificate", func(t *testing.T) {
		h, _ := configHarness(t, profileConfig)
		h.secrets[refCert] = vectorCA
		h.stdinTTY = true
		code, stdout, stderr := h.run("--profile", "prod", "ca", "show")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stdout, "Fingerprint: "+vectorFingerprint)
		assert.Equal(t, []string{refCert}, h.resolved, "references read")
	})

	t.Run("stdin wins", func(t *testing.T) {
		h, _ := configHarness(t, profileConfig)
		h.stdin = vectorCA
		code, stdout, stderr := h.run("--profile", "prod", "ca", "show")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stdout, "Fingerprint: "+vectorFingerprint)
		assert.Empty(t, h.resolved, "references read")
	})

	t.Run("not set", func(t *testing.T) {
		h, path := configHarness(t, "profiles:\n  prod: {}\n")
		h.stdinTTY = true
		code, _, stderr := h.run("--profile", "prod", "ca", "show")
		assert.Equal(t, 1, code, "exit code")
		assert.Equal(t, "aopctl: ca show reads the CA certificate PEM from stdin or ca_cert: pipe it in, for example with op read, or set ca_cert in profile prod of "+path+"\n", stderr, "stderr")
	})
}

func TestQuoteArg(t *testing.T) {
	tests := []struct {
		in, posix, windows string
	}{
		{"/home/me/.config/aopctl/config.yaml", "/home/me/.config/aopctl/config.yaml", "/home/me/.config/aopctl/config.yaml"},
		{"/my configs/a.yaml", "'/my configs/a.yaml'", "'/my configs/a.yaml'"},
		{"it's.yaml", `'it'\''s.yaml'`, "'it''s.yaml'"},
		{"$(rm -rf x)`y`.yaml", "'$(rm -rf x)`y`.yaml'", "'$(rm -rf x)`y`.yaml'"},
		{`/tmp/config\name.yaml`, `'/tmp/config\name.yaml'`, `'/tmp/config\name.yaml'`},
		{`C:\Users\Jim Smith\config.yaml`, `'C:\Users\Jim Smith\config.yaml'`, `'C:\Users\Jim Smith\config.yaml'`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.posix, quoteArg(tt.in, "linux"), "POSIX")
			assert.Equal(t, tt.windows, quoteArg(tt.in, "windows"), "PowerShell")
			if runtime.GOOS == "windows" {
				return
			}
			out, err := exec.CommandContext(t.Context(), "sh", "-c", "printf %s "+quoteArg(tt.in, "linux")).Output() //nolint:gosec // the shell parses the quoted test input on purpose
			require.NoError(t, err, "sh")
			assert.Equal(t, tt.in, string(out), "sh round trip")
		})
	}
}
