package aopctl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const pollInterval = 5 * time.Second

// isTransient reports whether a polling read may succeed if retried: HTTP
// 429, a 5xx, or a transport error. Callers check the budget first.
func isTransient(err error) bool {
	apiErr, ok := errors.AsType[*apiError](err)
	if !ok {
		return false
	}
	return apiErr.transport || apiErr.status == http.StatusTooManyRequests || apiErr.status >= 500
}

// certGetter reads one hostname or zone certificate.
type certGetter func(ctx context.Context, id string) (*Certificate, error)

// waitForCert polls an uploaded certificate until it is active.
func (c *Client) waitForCert(ctx context.Context, get certGetter, id string) error {
	last := "last status unknown"
	timedOut := func(err error) error {
		return &timeoutError{msg: fmt.Sprintf("timed out waiting for certificate %s to become active: %s", id, last), err: err}
	}
	for {
		cert, err := get(ctx, id)
		switch {
		case err == nil:
			last = "last status " + cert.Status
			switch cert.Status {
			case statusActive:
				return nil
			case statusDeploymentTimedOut, statusDeletionTimedOut, statusPendingDeletion, statusDeleted:
				return fmt.Errorf("certificate %s is %s", id, cert.Status)
			}
		case ctx.Err() != nil:
			return timedOut(ctx.Err())
		case isTransient(err):
			last = "last error: " + err.Error()
		default:
			return fmt.Errorf("check certificate %s: %w", id, err)
		}
		if err := c.wait(ctx, pollInterval); err != nil {
			return timedOut(err)
		}
	}
}

// waitForAssociations polls until every hostname points at id and is active,
// recording what it sees in observed.
func (c *Client) waitForAssociations(ctx context.Context, id string, hosts []string, observed map[string]*Association) error {
	pending := hosts
	// lastErr holds a hostname's transient read error, if its last read failed.
	lastErr := map[string]error{}
	for {
		var still []string
		for i, h := range pending {
			assoc, err := c.cf.getAssociation(ctx, h)
			if err != nil {
				if ctx.Err() != nil {
					return associationTimeout(id, append(still, pending[i:]...), observed, lastErr, ctx.Err())
				}
				if !isTransient(err) {
					return fmt.Errorf("check association for %s: %w", h, err)
				}
				lastErr[h] = err
				still = append(still, h)
				continue
			}
			delete(lastErr, h)
			observed[h] = assoc
			// A timed-out association still on another certificate has not
			// switched yet.
			if assoc != nil && assoc.CertID == id && strings.HasSuffix(assoc.Status, "_timed_out") {
				return fmt.Errorf("association for %s is %s", h, assoc.Status)
			}
			if assoc == nil || assoc.CertID != id || assoc.Status != statusActive {
				still = append(still, h)
			}
		}
		pending = still
		if len(pending) == 0 {
			return nil
		}
		if err := c.wait(ctx, pollInterval); err != nil {
			return associationTimeout(id, pending, observed, lastErr, err)
		}
	}
}

func associationTimeout(id string, pending []string, observed map[string]*Association, lastErr map[string]error, err error) error {
	states := make([]string, len(pending))
	for i, h := range pending {
		state := "unknown"
		if err := lastErr[h]; err != nil {
			state = "error: " + err.Error()
		} else if assoc, ok := observed[h]; ok {
			state = assoc.String()
		}
		states[i] = h + ": " + state
	}
	return &timeoutError{
		msg: fmt.Sprintf("timed out waiting for hostnames to use certificate %s: last observed %s", id, strings.Join(states, "; ")),
		err: err,
	}
}

// waitForDeletion polls until the certificate is gone or deleted.
func (c *Client) waitForDeletion(ctx context.Context, get certGetter, id string) error {
	last := "last status unknown"
	timedOut := func(err error) error {
		return &timeoutError{msg: "timed out waiting for the delete to finish: " + last, err: err}
	}
	for {
		cert, err := get(ctx, id)
		switch {
		case isNotFound(err):
			return nil
		case err == nil:
			last = "last status " + cert.Status
			switch cert.Status {
			case statusDeleted:
				return nil
			case statusDeletionTimedOut:
				return fmt.Errorf("the delete failed at Cloudflare: status %s", cert.Status)
			}
		case ctx.Err() != nil:
			return timedOut(ctx.Err())
		case isTransient(err):
			last = "last error: " + err.Error()
		default:
			return fmt.Errorf("check certificate: %w", err)
		}
		if err := c.wait(ctx, pollInterval); err != nil {
			return timedOut(err)
		}
	}
}
