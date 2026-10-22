//go:build !windows

package cli

import (
	"io"
	"os"
)

// openTerminal opens the controlling terminal.
func openTerminal() (io.ReadWriteCloser, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}
