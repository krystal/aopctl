package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// maxConfigSize caps the config file, which holds a few PEM blocks at most.
const maxConfigSize = 1 << 20

// setting is a value aopctl reads from the config file, or from the
// environment when no config file is in use.
type setting struct {
	env string
	key string
}

var (
	settingCACert    = setting{env: "AOP_CA_CERT", key: "ca_cert"}
	settingCAKey     = setting{env: "AOP_CA_KEY", key: "ca_key"}
	settingToken     = setting{env: "CLOUDFLARE_API_TOKEN", key: "cloudflare_api_token"}
	settingZoneID    = setting{env: "CLOUDFLARE_ZONE_ID", key: "cloudflare_zone_id"}
	settingHostnames = setting{env: "AOP_HOSTNAMES", key: "hostnames"}
)

// fileSettings are the settings at the top of the config file or in one of
// its profiles. A nil Hostnames is unset, and an empty one is set to none.
type fileSettings struct {
	CACert    string   `yaml:"ca_cert"`
	CAKey     string   `yaml:"ca_key"`
	Token     string   `yaml:"cloudflare_api_token"`
	ZoneID    string   `yaml:"cloudflare_zone_id"`
	Hostnames []string `yaml:"hostnames"`
}

// fileConfig is the config file: settings that apply to every profile, and
// the profiles, whose settings override them.
type fileConfig struct {
	fileSettings `yaml:",inline"`

	Profiles map[string]fileSettings `yaml:"profiles"`
}

// overlay returns s with the settings p sets replacing its own.
func (s fileSettings) overlay(p fileSettings) fileSettings {
	if p.CACert != "" {
		s.CACert = p.CACert
	}
	if p.CAKey != "" {
		s.CAKey = p.CAKey
	}
	if p.Token != "" {
		s.Token = p.Token
	}
	if p.ZoneID != "" {
		s.ZoneID = p.ZoneID
	}
	if p.Hostnames != nil {
		s.Hostnames = p.Hostnames
	}
	return s
}

func (s fileSettings) value(st setting) string {
	switch st {
	case settingCACert:
		return s.CACert
	case settingCAKey:
		return s.CAKey
	case settingToken:
		return s.Token
	case settingZoneID:
		return s.ZoneID
	}
	return ""
}

// profileNamePattern keeps profile names free of anything a shell would
// need quoted, as printed commands carry --profile.
var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// configFile is a decoded config file.
type configFile struct {
	// path is the file's absolute path.
	path string
	fileConfig
	// warnings are printed once by a command that reads settings.
	warnings []string
}

func (f *configFile) profileNames() []string {
	names := make([]string, 0, len(f.Profiles))
	for name := range f.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// config is where a command's settings come from: a config file with the
// profile's settings merged in, or the environment when file is nil.
type config struct {
	file     *configFile
	profile  string
	settings fileSettings
}

// where names the config file and profile in messages.
func (c *config) where() string {
	if c.profile != "" {
		return fmt.Sprintf("profile %s of %s", c.profile, c.file.path)
	}
	return c.file.path
}

// defaultConfigDir is where the config file is by default: the XDG config
// directory on Unix, macOS included, and %AppData% on Windows.
func defaultConfigDir() (string, error) {
	if runtime.GOOS == "windows" {
		return os.UserConfigDir()
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(dir) {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config"), nil
}

// defaultConfigHint is the default config file path for help text.
func defaultConfigHint() string {
	if runtime.GOOS == "windows" {
		return `%AppData%\aopctl\config.yaml`
	}
	return "~/.config/aopctl/config.yaml, or under $XDG_CONFIG_HOME/aopctl"
}

// flagChanged reports whether the persistent flag name was given.
func (a *app) flagChanged(name string) bool {
	return a.root != nil && a.root.PersistentFlags().Changed(name)
}

// configPath finds the config file: --config, then AOPCTL_CONFIG, then the
// default path if the file exists there. "" means no config file.
func (a *app) configPath() (string, error) {
	if a.flagChanged("config") {
		if strings.TrimSpace(a.configFlag) == "" {
			return "", usagef("--config must not be empty")
		}
		return a.configFlag, nil
	}
	if v := strings.TrimSpace(a.getenv("AOPCTL_CONFIG")); v != "" {
		return v, nil
	}
	if a.configDir == nil {
		return "", nil
	}
	dir, err := a.configDir()
	if err != nil {
		// Without a home directory there is no default path.
		return "", nil
	}
	path := filepath.Join(dir, "aopctl", "config.yaml")
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return path, nil
}

// readConfigFile reads and decodes the config file once. It returns nil
// when no config file is in use.
func (a *app) readConfigFile() (*configFile, error) {
	if !a.fileRead {
		a.fileRead = true
		a.file, a.fileErr = a.loadConfigFile()
	}
	return a.file, a.fileErr
}

func (a *app) loadConfigFile() (*configFile, error) {
	path, err := a.configPath()
	if err != nil || path == "" {
		return nil, err
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	f, err := os.Open(path) //nolint:gosec // the user names the config file
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("config file %s is larger than %d bytes", path, maxConfigSize)
	}

	file := &configFile{path: path}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&file.fileConfig); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config file %s: %w", path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config file %s: want a single YAML document", path)
	}
	for _, name := range file.profileNames() {
		if !profileNamePattern.MatchString(name) {
			return nil, fmt.Errorf("config file %s: invalid profile name %q: want letters, digits, '_', '.' and '-', starting with a letter or digit", path, name)
		}
	}
	if info, err := f.Stat(); err == nil {
		file.warnings = permissionWarnings(path, info.Mode(), &file.fileConfig)
	}
	return file, nil
}

// permissionWarnings warns about a config file that other users can read
// and that holds a secret itself rather than a reference to it. Windows
// file modes do not reflect who can read a file.
func permissionWarnings(path string, mode fs.FileMode, fc *fileConfig) []string {
	if runtime.GOOS == "windows" || mode.Perm()&0o044 == 0 {
		return nil
	}
	all := append([]fileSettings{fc.fileSettings}, mapValues(fc.Profiles)...)
	var literal []string
	for _, st := range []setting{settingCAKey, settingToken} {
		for _, s := range all {
			if v := strings.TrimSpace(s.value(st)); v != "" && !isReference(v) {
				literal = append(literal, st.key)
				break
			}
		}
	}
	if len(literal) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("Warning: %s is readable by other users and holds a literal %s: run chmod 600 on it, or use op:// references.", path, strings.Join(literal, " and "))}
}

func mapValues[K comparable, V any](m map[K]V) []V {
	values := make([]V, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// selectedProfile returns the profile --profile or AOPCTL_PROFILE names.
func (a *app) selectedProfile() string {
	if a.flagChanged("profile") {
		return strings.TrimSpace(a.profileFlag)
	}
	return strings.TrimSpace(a.getenv("AOPCTL_PROFILE"))
}

// config returns where settings come from, once. A config file in use is
// the only source of settings, but for the token's fallback to the
// environment.
func (a *app) config() (*config, error) {
	if a.cfg == nil && a.cfgErr == nil {
		a.cfg, a.cfgErr = a.loadConfig()
	}
	return a.cfg, a.cfgErr
}

func (a *app) loadConfig() (*config, error) {
	file, err := a.readConfigFile()
	if err != nil {
		return nil, err
	}
	profile := a.selectedProfile()
	if file == nil {
		if profile != "" {
			return nil, usagef("profile %s needs a config file: pass --config or set AOPCTL_CONFIG", profile)
		}
		return &config{}, nil
	}
	c := &config{file: file, profile: profile, settings: file.fileSettings}
	names := file.profileNames()
	switch {
	case len(names) == 0 && profile != "":
		return nil, usagef("profile %s: %s has no profiles", profile, file.path)
	case len(names) == 0:
	case profile == "":
		return nil, usagef("no profile: pass --profile or set AOPCTL_PROFILE to one of %s in %s", strings.Join(names, ", "), file.path)
	default:
		p, ok := file.Profiles[profile]
		if !ok {
			return nil, usagef("unknown profile %q: want one of %s in %s", profile, strings.Join(names, ", "), file.path)
		}
		c.settings = c.settings.overlay(p)
	}
	return c, nil
}

// raw returns the configured value of s, unresolved and trimmed, and the
// name messages use for it: its key in the config file, or its environment
// variable. The token falls back to the environment when the config file
// sets none.
func (c *config) raw(s setting, getenv func(string) string) (value, name string) {
	if c.file == nil {
		return strings.TrimSpace(getenv(s.env)), s.env
	}
	if v := strings.TrimSpace(c.settings.value(s)); v != "" || s != settingToken {
		return v, s.key
	}
	if v := strings.TrimSpace(getenv(s.env)); v != "" {
		return v, s.env
	}
	return "", s.key
}

// name is how messages refer to s, as the user configured it.
func (a *app) name(s setting) string {
	c, err := a.config()
	if err != nil {
		return s.env
	}
	_, name := c.raw(s, a.getenv)
	return name
}

// commandConfig is config for a command that reads settings, which prints
// the config file's warnings once.
func (a *app) commandConfig(cmd *cobra.Command) (*config, error) {
	c, err := a.config()
	if err != nil {
		return nil, err
	}
	if !a.warned && c.file != nil {
		a.warned = true
		for _, w := range c.file.warnings {
			fmt.Fprintln(cmd.ErrOrStderr(), w)
		}
	}
	return c, nil
}

// lookup returns the value of s, reading a 1Password secret reference, or
// "" when s is not set.
func (a *app) lookup(cmd *cobra.Command, s setting) (string, error) {
	c, err := a.commandConfig(cmd)
	if err != nil {
		return "", err
	}
	v, name := c.raw(s, a.getenv)
	if c.file != nil && s == settingToken && name == s.env && !a.tokenNoted {
		a.tokenNoted = true
		fmt.Fprintf(cmd.ErrOrStderr(), "Note: %s sets no %s, so aopctl uses %s from the environment.\n", c.where(), s.key, s.env)
	}
	if !isReference(v) {
		return v, nil
	}
	return a.resolveReference(cmd.Context(), name, v)
}

func (a *app) resolveReference(ctx context.Context, name, ref string) (string, error) {
	v, err := a.resolve(ctx, ref)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("resolve %s (%s): %w", name, ref, err)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%s: %s resolved to an empty value", name, ref)
	}
	return v, nil
}

// require is lookup for a setting the command needs.
func (a *app) require(cmd *cobra.Command, s setting) (string, error) {
	v, err := a.lookup(cmd, s)
	if err != nil || v != "" {
		return v, err
	}
	c, _ := a.config()
	switch {
	case c.file == nil:
		return "", fmt.Errorf("%s is not set", s.env)
	case s == settingToken:
		return "", fmt.Errorf("%s is not set in %s, and %s is not set", s.key, c.where(), s.env)
	}
	return "", fmt.Errorf("%s is not set in %s", s.key, c.where())
}

// configuredHostnames returns the config file's hostnames, or the
// AOP_HOSTNAMES entries, split on commas and whitespace.
func (a *app) configuredHostnames() ([]string, error) {
	c, err := a.config()
	if err != nil {
		return nil, err
	}
	if c.file != nil {
		return c.settings.Hostnames, nil
	}
	return strings.FieldsFunc(a.getenv(settingHostnames.env), func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}), nil
}

// configuredZone returns the configured zone ID for a command run with the
// --zone z. A --zone takes precedence, so a reference that only it would
// replace is not read, and counts as no configured zone.
func (a *app) configuredZone(cmd *cobra.Command, z zoneArg) (string, error) {
	if z.given() {
		c, err := a.commandConfig(cmd)
		if err != nil {
			return "", err
		}
		if v, _ := c.raw(settingZoneID, a.getenv); isReference(v) {
			return "", nil
		}
	}
	return a.lookup(cmd, settingZoneID)
}

// completeProfiles offers the config file's profiles, without reading any
// secret.
func (a *app) completeProfiles(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	file, err := a.readConfigFile()
	if err != nil || file == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return file.profileNames(), cobra.ShellCompDirectiveNoFileComp
}

// configFlags are the --config and --profile flags given, for printed
// commands.
func (a *app) configFlags() string {
	var b strings.Builder
	if a.flagChanged("config") && strings.TrimSpace(a.configFlag) != "" {
		path := a.configFlag
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		b.WriteString(" --config " + quoteArg(path, runtime.GOOS))
	}
	if a.flagChanged("profile") && strings.TrimSpace(a.profileFlag) != "" {
		b.WriteString(" --profile " + quoteArg(strings.TrimSpace(a.profileFlag), runtime.GOOS))
	}
	return b.String()
}

// shellSafe matches arguments that need no quoting in POSIX shells or
// PowerShell.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9@%_+=:,./-]+$`)

// quoteArg quotes s for a POSIX shell, or for PowerShell on Windows, unless
// it needs no quoting.
func quoteArg(s, goos string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	if goos == "windows" {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
