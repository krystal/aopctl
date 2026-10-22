package aopctl

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrNotCA is returned for a CA certificate that is not a CA.
	ErrNotCA = errors.New("not a CA certificate")
	// ErrKeyMismatch is returned for a CA key that does not match the CA
	// certificate.
	ErrKeyMismatch = errors.New("the CA key does not match the CA certificate")
	// ErrPlanApplied is returned by a plan's second Apply.
	ErrPlanApplied = errors.New("plan already applied")
	// ErrNotAllDeleted is returned by HostnamePrunePlan.Apply when a target
	// was not deleted.
	ErrNotAllDeleted = errors.New("some certificates were not deleted")
)

// CAExpiryError reports a CA that expires before the leaf it would sign.
type CAExpiryError struct {
	CANotAfter   time.Time
	LeafNotAfter time.Time
}

func (e *CAExpiryError) Error() string {
	return fmt.Sprintf("the CA expires %s, before the new leaf would (%s)",
		e.CANotAfter.UTC().Format(time.RFC3339), e.LeafNotAfter.UTC().Format(time.RFC3339))
}

// NotSignedError reports a certificate that the CA did not sign.
type NotSignedError struct {
	CertID string
}

func (e *NotSignedError) Error() string {
	return fmt.Sprintf("certificate %s is not signed by the CA", e.CertID)
}

// CertificateLimitError reports a zone with no free slot for another
// hostname certificate.
type CertificateLimitError struct {
	Count int
	Limit int
}

func (e *CertificateLimitError) Error() string {
	return fmt.Sprintf("the zone has %d hostname certificates, Cloudflare's limit is %d: delete unused ones first", e.Count, e.Limit)
}

// UploadUnknownError reports an upload that may have created a certificate:
// the response was a 5xx, an unsuccessful 2xx, unreadable, or had no
// certificate ID. Check the zone's certificates before retrying.
type UploadUnknownError struct {
	// Err is the request's error, or nil when the response had no
	// certificate ID.
	Err error
}

func (e *UploadUnknownError) Error() string {
	if e.Err == nil {
		return "upload outcome unknown: the response has no certificate ID"
	}
	return fmt.Sprintf("upload outcome unknown: %v: a certificate may have been created", e.Err)
}

func (e *UploadUnknownError) Unwrap() error { return e.Err }

// HostnameRolloutError reports a new certificate that was uploaded but not
// rolled out to every hostname, with the state needed to resume or roll
// back.
type HostnameRolloutError struct {
	// CertID is the uploaded certificate.
	CertID    string
	Hostnames []string
	// Original holds each hostname's association before the rollout. A nil
	// value means none.
	Original map[string]*Association
	// Observed holds the last association read for each hostname. A
	// missing hostname is unknown, and a nil value means none.
	Observed map[string]*Association
	// SignedByCA records which hostname certificates the CA signed, keyed
	// by hostname certificate ID.
	SignedByCA map[string]bool
	// AssociateSent is set once the request to point the hostnames at
	// CertID was attempted. Until then, no hostname was changed.
	AssociateSent bool
	Err           error
}

func (e *HostnameRolloutError) Error() string { return e.Err.Error() }

func (e *HostnameRolloutError) Unwrap() error { return e.Err }

// timeoutError reports polling that ran out of time. It wraps the context
// or Wait error that ended it.
type timeoutError struct {
	msg string
	err error
}

func (e *timeoutError) Error() string { return e.msg }

func (e *timeoutError) Unwrap() error { return e.err }
