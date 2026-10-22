// Package cli is the aopctl command line. It manages a dedicated client CA
// for Cloudflare Authenticated Origin Pulls (AOP) and the per-hostname and
// zone-level leaf certificates it issues.
//
// Secrets come from environment variables, for example through
// "op run --env-file", and keys are never written to disk.
//
// Run is the entry point of the aopctl binary. Another cobra command can
// mount aopctl as a subcommand with NewCommand and map the error its
// Execute returns to an exit status with ExitCode.
package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/krystal/aopctl/aopctl"
)

const rootLong = `aopctl manages a dedicated client CA for Cloudflare Authenticated Origin
Pulls (AOP) and the per-hostname and zone-level leaf certificates it issues.

Secrets come from environment variables, for example through
"op run --env-file", and keys are never written to disk.

Environment:
  AOP_CA_CERT           CA certificate PEM
  AOP_CA_KEY            CA private key PEM (PKCS#8), for hostname and zone issue
  CLOUDFLARE_API_TOKEN  Zone > SSL and Certificates > Edit
  CLOUDFLARE_ZONE_ID    the zone's ID
  AOP_HOSTNAMES         hostnames this CA serves, comma- or space-separated,
                        for the hostname commands`

// modulePath is the module whose version aopctl reports.
const modulePath = "github.com/krystal/aopctl"

// Options configures the aopctl command.
type Options struct {
	// Version is what the version command and --version print. Release
	// builds of the aopctl binary set it. Empty means the version of the
	// github.com/krystal/aopctl module in the build info, so a command that
	// mounts aopctl reports aopctl's version rather than its own.
	Version string

	// Getenv reads the environment variables aopctl takes its secrets and
	// hostnames from. Nil means os.Getenv. A command that mounts aopctl can
	// supply the values from elsewhere.
	Getenv func(string) string
}

// NewCommand returns the aopctl command. Add it to another cobra command to
// mount aopctl as a subcommand: its printed commands then start with the
// full command path, its errors print with an "aopctl:" prefix unless the
// root command silences them, and ExitCode maps the error Execute returns
// to aopctl's exit status. The help and completion commands are then the
// other command's.
//
// Build a new command for each Execute, as cobra keeps flag values between
// runs. To run aopctl as a program, use Run, which also adds the help and
// completion commands with aopctl's usage errors.
func NewCommand(opts Options) *cobra.Command {
	return newRootCmd(newApp(opts))
}

// Run runs aopctl with args, the command line without the program name,
// prints any error to stderr and returns the exit status. ctx cancels the
// command, for example on an interrupt.
func Run(ctx context.Context, args []string, opts Options) int {
	return execute(ctx, NewCommand(opts), args)
}

// ExitCode returns the exit status for an error from executing the aopctl
// command, mounted or not: 0 for nil, 2 for usage errors and 1 otherwise.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if _, ok := errors.AsType[*usageError](err); ok {
		return 2
	}
	return 1
}

// execute runs the root command cmd and prints its error as aopctl does.
func execute(ctx context.Context, cmd *cobra.Command, args []string) int {
	// cobra reads os.Args when args is nil.
	if args == nil {
		args = []string{}
	}
	cmd.SetArgs(args)
	cmd.SilenceErrors = true
	initStandalone(cmd, args)
	err := cmd.ExecuteContext(ctx)
	if e, ok := errors.AsType[*usageError](err); ok && e.helpShown {
		// The help says it all.
		return ExitCode(err)
	}
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "aopctl: %v\n", err)
	}
	return ExitCode(err)
}

// initStandalone adds cobra's help and completion commands to the aopctl
// root cmd, which cobra would add when it executes, and makes them exit
// with status 2 on bad arguments as the aopctl commands do. When aopctl is
// mounted, these commands belong to the host's root instead.
func initStandalone(cmd *cobra.Command, args []string) {
	cmd.InitDefaultHelpCmd()
	cmd.InitDefaultCompletionCmd(args...)
	for _, sub := range cmd.Commands() {
		switch sub.Name() {
		case "help":
			// cobra's help prints the closest help it finds for an unknown
			// command.
			sub.Args = helpArgs
		case "completion":
			sub.Args = noArgs
			sub.RunE = helpUsage
			for _, shell := range sub.Commands() {
				shell.Args = noArgs
			}
		}
	}
}

// helpArgs rejects a help topic that is not a command, as that command
// would reject the arguments left over.
func helpArgs(cmd *cobra.Command, args []string) error {
	topic, rest, err := cmd.Root().Find(args)
	if err != nil {
		return commandLineError(cmd, err)
	}
	return noArgs(topic, rest)
}

type app struct {
	getenv func(string) string

	// stdoutIsTerminal and stdinIsTerminal check the command's output and
	// input.
	stdoutIsTerminal func(io.Writer) bool
	stdinIsTerminal  func(io.Reader) bool
	// openTTY opens the terminal for confirmation prompts: the controlling
	// terminal, or the console on Windows. Either works under op run
	// whatever stdin and stdout are.
	openTTY func() (io.ReadWriteCloser, error)

	// baseURL, now and wait are the library's test seams. Empty and nil
	// values mean its defaults.
	baseURL string
	wait    func(ctx context.Context, d time.Duration) error
	now     func() time.Time

	version string

	// root is the aopctl command, whose path starts printed commands.
	root *cobra.Command
}

func newApp(opts Options) *app {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	return &app{
		getenv:           getenv,
		stdoutIsTerminal: func(w io.Writer) bool { return isTerminal(w) },
		stdinIsTerminal:  func(r io.Reader) bool { return isTerminal(r) },
		openTTY:          openTerminal,
		now:              time.Now,
		version:          resolveVersion(opts.Version, debug.ReadBuildInfo),
	}
}

// resolveVersion prefers the version a release build sets, then the version
// of this module that the build info records: the main module's for
// "go install module@version", or a dependency's when another command
// mounts aopctl.
func resolveVersion(buildVersion string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if buildVersion != "" {
		return buildVersion
	}
	info, ok := readBuildInfo()
	if !ok {
		return "(devel)"
	}
	mod := &info.Main
	if mod.Path != modulePath {
		mod = nil
		for _, dep := range info.Deps {
			if dep.Path == modulePath {
				mod = dep
				break
			}
		}
	}
	if mod != nil && mod.Replace != nil {
		mod = mod.Replace
	}
	if mod != nil && mod.Version != "" {
		return mod.Version
	}
	return "(devel)"
}

// isTerminal reports whether v is a terminal. Only an *os.File can be one,
// and a device that is not a terminal, such as os.DevNull, does not count.
func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// commandPath is how printed commands start: "aopctl", or the full path
// when aopctl is mounted under another command.
func (a *app) commandPath() string {
	return a.root.CommandPath()
}

func newRootCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "aopctl",
		Short:   "Manage Cloudflare Authenticated Origin Pulls certificates",
		Long:    rootLong,
		Version: a.version,
		Args:    noArgs,
		RunE:    helpUsage,
	}
	a.root = cmd
	cmd.SetVersionTemplate("aopctl {{.Version}}\n")
	cmd.SetErrPrefix("aopctl:")
	// Children inherit these, so they apply when aopctl is mounted too.
	cmd.SetFlagErrorFunc(commandLineError)
	cmd.CompletionOptions.SetDefaultShellCompDirective(cobra.ShellCompDirectiveNoFileComp)
	cmd.AddCommand(newCACmd(a), newHostnameCmd(a), newZoneCmd(a), newVersionCmd(a))
	silenceUsage(cmd)
	return cmd
}

// newGroupCmd returns a command that only holds subcommands.
func newGroupCmd(use, short string, subs ...*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  noArgs,
		RunE:  helpUsage,
	}
	cmd.AddCommand(subs...)
	return cmd
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the aopctl version",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "aopctl %s\n", a.version)
			return nil
		},
	}
}

// silenceUsage stops cobra printing the usage after an error on every
// command, as it checks only the failing command and the root, which is
// another program's when aopctl is mounted.
func silenceUsage(cmd *cobra.Command) {
	cmd.SilenceUsage = true
	for _, sub := range cmd.Commands() {
		silenceUsage(sub)
	}
}

// helpUsage prints the help to stderr for a command run without a
// subcommand, and exits with status 2.
func helpUsage(cmd *cobra.Command, _ []string) error {
	// This is what cmd.Help prints with cobra's default help template, but
	// to stderr, without changing the command's writers.
	w := cmd.ErrOrStderr()
	if desc := strings.TrimRightFunc(cmp.Or(cmd.Long, cmd.Short), unicode.IsSpace); desc != "" {
		fmt.Fprintf(w, "%s\n\n", desc)
	}
	fmt.Fprint(w, cmd.UsageString())
	return &usageError{msg: cmd.CommandPath() + " requires a subcommand", helpShown: true}
}

// usageError exits with status 2. helpShown means the help was printed
// instead, so execute prints nothing more. A command that mounts aopctl
// prints the message after the help unless it silences errors.
type usageError struct {
	msg       string
	helpShown bool
}

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// commandLineError makes err, about a flag, an argument or an unknown
// command, a usage error that points at the command's help.
func commandLineError(cmd *cobra.Command, err error) error {
	return usagef("%v\nRun '%s --help' for usage.", err, cmd.CommandPath())
}

// noArgs rejects positional arguments, which are unknown commands for a
// group command, as a usage error.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if cmd.HasSubCommands() {
		return commandLineError(cmd, cobra.NoArgs(cmd, args))
	}
	return commandLineError(cmd, fmt.Errorf("unexpected argument %q", args[0]))
}

var keyTypes = []cobra.Completion{string(aopctl.KeyTypeECP256), string(aopctl.KeyTypeRSA3072)}

func keyTypeFlag(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVar(p, "key-type", string(aopctl.KeyTypeECP256), "key type: "+string(aopctl.KeyTypeECP256)+" or "+string(aopctl.KeyTypeRSA3072))
	_ = cmd.RegisterFlagCompletionFunc("key-type", cobra.FixedCompletions(keyTypes, cobra.ShellCompDirectiveNoFileComp))
}

func dryRunFlag(cmd *cobra.Command, p *bool, usage string) {
	cmd.Flags().BoolVarP(p, "dry-run", "n", false, usage)
}

func timeoutFlag(cmd *cobra.Command, p *time.Duration) {
	cmd.Flags().DurationVar(p, "timeout", defaultTimeout, "time budget for the whole command")
}

func validateKeyType(keyType string) error {
	if k := aopctl.KeyType(keyType); k != aopctl.KeyTypeECP256 && k != aopctl.KeyTypeRSA3072 {
		return usagef("invalid --key-type %q: want %s or %s", keyType, aopctl.KeyTypeECP256, aopctl.KeyTypeRSA3072)
	}
	return nil
}

func validateDays(days int) error {
	if days <= 0 {
		return usagef("--days must be positive, got %d", days)
	}
	return nil
}

func validateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return usagef("--timeout must be positive, got %s", timeout)
	}
	return nil
}

func (a *app) requireEnv(name string) (string, error) {
	v := strings.TrimSpace(a.getenv(name))
	if v == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	return v, nil
}

func (a *app) client() (*aopctl.Client, error) {
	token, err := a.requireEnv("CLOUDFLARE_API_TOKEN")
	if err != nil {
		return nil, err
	}
	zoneID, err := a.requireEnv("CLOUDFLARE_ZONE_ID")
	if err != nil {
		return nil, err
	}
	return aopctl.NewClient(token, zoneID, aopctl.Options{BaseURL: a.baseURL, Now: a.now, Wait: a.wait})
}
