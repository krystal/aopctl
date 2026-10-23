package aopctl

import (
	"context"
	"errors"
	"net/http"
	"time"
)

const (
	defaultBaseURL = "https://api.cloudflare.com/client/v4"
	requestTimeout = 30 * time.Second
)

// Options configures a Client or a ZoneFinder. The zero value uses
// Cloudflare's API and the real clock. A ZoneFinder uses only HTTPClient
// and BaseURL.
type Options struct {
	// HTTPClient sends the API requests. Nil means a client with a
	// 30-second timeout.
	HTTPClient *http.Client
	// BaseURL replaces Cloudflare's API base URL,
	// https://api.cloudflare.com/client/v4, for example with a fake's.
	BaseURL string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Wait pauses between polls for d, or until ctx ends. An error ends
	// the polling, which then reports a timeout that wraps the error. Nil
	// means a timer.
	Wait func(ctx context.Context, d time.Duration) error
}

// Client runs the aopctl workflows against one Cloudflare zone. To find a
// hostname's zone, use a ZoneFinder.
type Client struct {
	cf   *cfClient
	now  func() time.Time
	wait func(ctx context.Context, d time.Duration) error
}

// NewClient returns a Client for the zone. The API token needs the zone's
// SSL and Certificates permission: Read for HostnameStatus and ZoneStatus,
// and Edit for the other workflows.
func NewClient(apiToken, zoneID string, opts Options) (*Client, error) {
	if apiToken == "" {
		return nil, errors.New("no API token")
	}
	if zoneID == "" {
		return nil, errors.New("no zone ID")
	}
	c := &Client{
		cf:   newCFClient(apiToken, zoneID, opts),
		now:  opts.Now,
		wait: opts.Wait,
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.wait == nil {
		c.wait = sleep
	}
	return c, nil
}

// newCFClient applies the defaults of opts. zoneID is "" for requests
// outside a zone.
func newCFClient(apiToken, zoneID string, opts Options) *cfClient {
	cf := &cfClient{
		baseURL: opts.BaseURL,
		token:   apiToken,
		zoneID:  zoneID,
		http:    opts.HTTPClient,
	}
	if cf.baseURL == "" {
		cf.baseURL = defaultBaseURL
	}
	if cf.http == nil {
		cf.http = &http.Client{Timeout: requestTimeout}
	}
	return cf
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
