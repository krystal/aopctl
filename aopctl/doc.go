// Package aopctl manages a dedicated client CA for Cloudflare Authenticated
// Origin Pulls (AOP) and the per-hostname leaf certificates it issues. It is
// the library behind the aopctl command.
//
// The package reads no environment variables, writes nothing to standard
// output or standard error, and never prompts. Callers supply the inputs,
// render plans and results, and ask for any confirmation themselves.
//
// Workflows that change Cloudflare state come in two steps. A Plan method
// checks the inputs and reads the zone without changing anything, and the
// plan's Apply makes the changes, at most once. Apply reports progress
// through the request's Progress callback and returns typed errors, such as
// *UploadUnknownError and *HostnameRolloutError, that carry what a caller
// needs to resume or roll back. A context deadline is the time budget for
// both steps.
//
// A Client is safe for concurrent use. Plans are not.
package aopctl
