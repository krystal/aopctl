// Command aopctl manages a dedicated client CA for Cloudflare Authenticated
// Origin Pulls (AOP) and the per-hostname and zone-level leaf certificates
// it issues.
//
// Secrets come from environment variables, for example through
// "op run --env-file", and keys are never written to disk.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/krystal/aopctl/cli"
)

// version is set by release builds with -ldflags "-X main.version=...".
var version string

func main() {
	// Interrupts cancel the command's context, so it stops cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.Options{Version: version})
	stop()
	os.Exit(code)
}
