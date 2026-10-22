//go:build windows

package cli

import (
	"errors"
	"io"
	"os"
)

// openTerminal opens the console, which Windows has instead of /dev/tty.
func openTerminal() (io.ReadWriteCloser, error) {
	return openConsole("CONIN$", "CONOUT$")
}

// openConsole opens the console's input and output as one terminal. Both
// are opened for reading and writing: Go writes UTF-8 to a console only
// when it can read the handle's console mode, which needs read access.
func openConsole(inName, outName string) (io.ReadWriteCloser, error) {
	in, err := os.OpenFile(inName, os.O_RDWR, 0) //nolint:gosec // the console, or temporary files in tests
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile(outName, os.O_RDWR, 0) //nolint:gosec // the console, or temporary files in tests
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	return &console{in: in, out: out}, nil
}

// console reads from the console's input and writes to its output.
type console struct {
	in, out *os.File
}

func (c *console) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *console) Write(p []byte) (int, error) { return c.out.Write(p) }

// Close closes both, even when closing the input fails.
func (c *console) Close() error {
	return errors.Join(c.in.Close(), c.out.Close())
}
