//go:build windows

package cli

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

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
