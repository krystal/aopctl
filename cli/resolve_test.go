package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain runs the test binary as a fake 1Password CLI when a test copies
// it in as op.
func TestMain(m *testing.M) {
	if mode := os.Getenv("AOPCTL_FAKE_OP"); mode != "" {
		os.Exit(fakeOp(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeOp acts as op does in mode: "value" prints FAKE_OP_VALUE for "op read
// --no-newline FAKE_OP_REF", "fail" prints FAKE_OP_STDERR and exits with 1,
// and "block" creates FAKE_OP_MARKER and waits to be killed.
func fakeOp(mode string, args []string) int {
	switch mode {
	case "value":
		if want := "read --no-newline " + os.Getenv("FAKE_OP_REF"); strings.Join(args, " ") != want {
			fmt.Fprintf(os.Stderr, "got arguments %q, want %q\n", args, want)
			return 3
		}
		fmt.Fprint(os.Stdout, os.Getenv("FAKE_OP_VALUE"))
		return 0
	case "fail":
		fmt.Fprint(os.Stderr, os.Getenv("FAKE_OP_STDERR"))
		return 1
	case "block":
		if err := os.WriteFile(os.Getenv("FAKE_OP_MARKER"), nil, 0o600); err != nil { //nolint:gosec // a path the test chose
			return 4
		}
		time.Sleep(time.Minute)
		return 0
	}
	return 2
}

// installFakeOp puts a fake op working in mode on a PATH of its own, and
// returns its directory.
func installFakeOp(t *testing.T, mode string) string {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err, "test binary")
	dir := t.TempDir()
	name := "op"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	src, err := os.Open(self) //nolint:gosec // the test binary
	require.NoError(t, err, "open test binary")
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY, 0o700) //nolint:gosec // a test directory
	require.NoError(t, err, "create fake op")
	_, err = io.Copy(dst, src)
	require.NoError(t, err, "copy fake op")
	require.NoError(t, dst.Close(), "close fake op")
	t.Setenv("PATH", dir)
	t.Setenv("AOPCTL_FAKE_OP", mode)
	return dir
}

func TestOpRead(t *testing.T) {
	const ref = "op://vault/item/field"

	t.Run("value", func(t *testing.T) {
		installFakeOp(t, "value")
		t.Setenv("FAKE_OP_REF", ref)
		t.Setenv("FAKE_OP_VALUE", "line 1\nline 2\n")
		v, err := opRead(t.Context(), ref)
		require.NoError(t, err, "opRead")
		assert.Equal(t, "line 1\nline 2\n", v, "value")
	})

	t.Run("not on PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := opRead(t.Context(), ref)
		assert.Equal(t, errOpNotFound, err, "error")
	})

	t.Run("only in the current directory", func(t *testing.T) {
		dir := installFakeOp(t, "value")
		t.Chdir(dir)
		t.Setenv("PATH", ".")
		_, err := opRead(t.Context(), ref)
		assert.Equal(t, errOpNotFound, err, "error")
	})

	t.Run("failure", func(t *testing.T) {
		long := strings.Repeat("é", 150)
		tests := []struct {
			name, stderr, want string
		}{
			{"last line only", "secret-looking first line\n[ERROR] 2026/01/02 15:04:05 \"item\" isn't an item\x1b[0m\n\n", "op exited with status 1: \"item\" isn't an item[0m"},
			{"no stderr", "", "op exited with status 1"},
			{"capped", long + "\n", "op exited with status 1: " + long[:196] + "..."},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				installFakeOp(t, "fail")
				t.Setenv("FAKE_OP_STDERR", tt.stderr)
				_, err := opRead(t.Context(), ref)
				require.Error(t, err)
				assert.Equal(t, tt.want, err.Error(), "error")
				assert.True(t, utf8.ValidString(err.Error()), "error is not valid UTF-8")
			})
		}
	})

	t.Run("cancel", func(t *testing.T) {
		installFakeOp(t, "block")
		marker := filepath.Join(t.TempDir(), "started")
		t.Setenv("FAKE_OP_MARKER", marker)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		a := &app{resolve: opRead}
		done := make(chan error, 1)
		go func() {
			_, err := a.resolveReference(ctx, "ca_key", ref)
			done <- err
		}()
		require.Eventually(t, func() bool {
			_, err := os.Stat(marker)
			return err == nil
		}, 10*time.Second, 10*time.Millisecond, "fake op did not start")
		cancel()
		select {
		case err := <-done:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(10 * time.Second):
			assert.Fail(t, "resolve did not return after cancelling")
		}
	})
}
