//go:build windows

package cli

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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

	reads    atomic.Int32 // Read calls in progress
	closed   atomic.Bool
	endReads sync.Once
}

// Read counts itself in reads before it checks closed, and Close sets
// closed before it checks reads, so Close always sees a Read that may reach
// the console.
func (c *console) Read(p []byte) (int, error) {
	c.reads.Add(1)
	defer c.reads.Add(-1)
	if c.closed.Load() {
		return 0, os.ErrClosed
	}
	return c.in.Read(p)
}

func (c *console) Write(p []byte) (int, error) { return c.out.Write(p) }

// Close closes both, even when closing the input fails. Closing the input
// waits for a pending read, which in line mode lasts until Enter, so Close
// first cancels console reads, repeating while a Read is in progress in case
// one reaches the console after a cancel.
func (c *console) Close() error {
	c.endReads.Do(func() {
		c.closed.Store(true)
		raw, err := c.in.SyscallConn()
		if err != nil {
			return
		}
		for c.reads.Load() > 0 {
			_ = raw.Control(func(fd uintptr) {
				_ = syscall.CancelIoEx(syscall.Handle(fd), nil)
			})
			time.Sleep(10 * time.Millisecond)
		}
	})
	return errors.Join(c.in.Close(), c.out.Close())
}
