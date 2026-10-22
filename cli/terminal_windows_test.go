//go:build windows

package cli

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenConsole(t *testing.T) {
	dir := t.TempDir()
	inName, outName := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	require.NoError(t, os.WriteFile(inName, []byte("y\r\n"), 0o600))
	require.NoError(t, os.WriteFile(outName, nil, 0o600))

	tty, err := openConsole(inName, outName)
	require.NoError(t, err, "openConsole")
	_, err = io.WriteString(tty, "Continue? [y/N] ")
	require.NoError(t, err, "write")
	got, err := io.ReadAll(tty)
	require.NoError(t, err, "read")
	assert.Equal(t, "y\r\n", string(got), "read")
	require.NoError(t, tty.Close(), "close")

	_, err = tty.Read(make([]byte, 1))
	assert.ErrorIs(t, err, os.ErrClosed, "read after close")
	_, err = tty.Write([]byte("x"))
	assert.ErrorIs(t, err, os.ErrClosed, "write after close")
	out, err := fs.ReadFile(os.DirFS(dir), "out")
	require.NoError(t, err)
	assert.Equal(t, "Continue? [y/N] ", string(out), "output file")
	in, err := fs.ReadFile(os.DirFS(dir), "in")
	require.NoError(t, err)
	assert.Equal(t, "y\r\n", string(in), "input file")
}

func TestOpenConsoleMissingOutput(t *testing.T) {
	dir := t.TempDir()
	inName := filepath.Join(dir, "in")
	require.NoError(t, os.WriteFile(inName, nil, 0o600))

	_, err := openConsole(inName, filepath.Join(dir, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist, "openConsole")
	// Windows cannot remove a file that is still open.
	assert.NoError(t, os.Remove(inName), "remove the input, which openConsole should have closed")
}

func TestConsoleCloseEndsPendingRead(t *testing.T) {
	tty, err := openTerminal()
	if err != nil {
		t.Skipf("no console: %v", err)
	}
	c, ok := tty.(*console)
	require.True(t, ok, "openTerminal returned %T", tty)

	type result struct {
		n   int
		err error
	}
	read := make(chan result, 1)
	go func() {
		n, err := c.Read(make([]byte, 64))
		read <- result{n, err}
	}()
	require.Eventually(t, func() bool { return c.reads.Load() > 0 || len(read) > 0 },
		10*time.Second, time.Millisecond, "Read never started")
	require.Empty(t, read, "Read ended before Close")

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		assert.NoError(t, err, "close")
	case <-time.After(10 * time.Second):
		require.FailNow(t, "Close blocked on the pending console read", "reads in progress: %d", c.reads.Load())
	}
	// Close returns only after the Read did.
	r := <-read
	// An error, not stray console input, ended the read.
	assert.Error(t, r.err, "pending read returned %d bytes", r.n)
}
