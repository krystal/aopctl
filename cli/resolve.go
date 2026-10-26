package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// referencePrefix starts a 1Password secret reference.
const referencePrefix = "op://"

// maxDiagnostic caps the line of op's stderr an error carries.
const maxDiagnostic = 200

func isReference(v string) bool {
	return strings.HasPrefix(v, referencePrefix)
}

var errOpNotFound = errors.New("the 1Password CLI (op) is not on PATH: install it, or run aopctl through op run")

// opRead reads a 1Password secret reference with the 1Password CLI. op
// gets no stdin: it asks for approval through the 1Password app, or uses
// OP_SERVICE_ACCOUNT_TOKEN.
//
// On failure, the error carries op's exit status and one line of its
// stderr, so that a misbehaving op cannot put more than that in aopctl's
// output.
func opRead(ctx context.Context, ref string) (string, error) {
	// An op found only through a relative PATH entry, such as the current
	// directory, counts as missing too (exec.ErrDot).
	op, err := exec.LookPath("op")
	if err != nil {
		return "", errOpNotFound
	}
	// ref is one argument, which no shell interprets.
	cmd := exec.CommandContext(ctx, op, "read", "--no-newline", ref) //nolint:gosec // G204: op is the 1Password CLI on PATH
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			if line := opDiagnostic(stderr.String()); line != "" {
				return "", fmt.Errorf("op exited with status %d: %s", exitErr.ExitCode(), line)
			}
			return "", fmt.Errorf("op exited with status %d", exitErr.ExitCode())
		}
		return "", fmt.Errorf("run op: %w", err)
	}
	return stdout.String(), nil
}

// opLogPrefix is how op starts its error lines, as in
// "[ERROR] 2026/01/02 15:04:05 ...".
var opLogPrefix = regexp.MustCompile(`^\[ERROR\] \d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)

// opDiagnostic returns the last non-empty line of op's stderr, without op's
// log prefix or control characters, and at most maxDiagnostic bytes long.
func opDiagnostic(stderr string) string {
	var last string
	for line := range strings.SplitSeq(stderr, "\n") {
		line = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, line)
		if line = strings.TrimSpace(line); line != "" {
			last = line
		}
	}
	last = opLogPrefix.ReplaceAllString(last, "")
	if len(last) > maxDiagnostic {
		cut := maxDiagnostic - len("...")
		for cut > 0 && !utf8.RuneStart(last[cut]) {
			cut--
		}
		last = last[:cut] + "..."
	}
	return last
}
