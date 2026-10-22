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

// Options configures a Client. The zero value uses Cloudflare's API and the
// real clock.
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

// Client runs the aopctl workflows against one Cloudflare zone.
type Client struct {
	cf   *cfClient
	now  func() time.Time
	wait func(ctx context.Context, d time.Duration) error
}

// NewClient returns a Client for the zone. The API token needs the zone's
// SSL and Certificates permission: Read for HostnameStatus, and Edit for
// the other workflows.
func NewClient(apiToken, zoneID string, opts Options) (*Client, error) {
	if apiToken == "" {
		return nil, errors.New("no API token")
	}
	if zoneID == "" {
		return nil, errors.New("no zone ID")
	}
	c := &Client{
		cf: &cfClient{
			baseURL: opts.BaseURL,
			token:   apiToken,
			zoneID:  zoneID,
			http:    opts.HTTPClient,
		},
		now:  opts.Now,
		wait: opts.Wait,
	}
	if c.cf.baseURL == "" {
		c.cf.baseURL = defaultBaseURL
	}
	if c.cf.http == nil {
		c.cf.http = &http.Client{Timeout: requestTimeout}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.wait == nil {
		c.wait = sleep
	}
	return c, nil
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
