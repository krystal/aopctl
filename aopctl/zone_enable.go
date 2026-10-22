package aopctl

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
)

// ZoneEnableRequest configures PlanZoneEnable.
type ZoneEnableRequest struct {
	// CACert must have signed the newest active zone-level certificate.
	CACert *x509.Certificate
}

// ZoneEnablePlan turns on zone-level AOP, checked against the zone. Its
// accessors return copies, and Apply acts only on what the plan captured.
type ZoneEnablePlan struct {
	client  *Client
	zone    *ZoneStatusReport
	ca      *x509.Certificate
	applied atomic.Bool
}

// PlanZoneEnable reads the zone-level setting and certificates. Unless
// zone-level AOP is already enabled, it fails without changing anything
// when the zone has no active certificate, with ErrNoActiveCertificate, or
// when the CA did not sign the newest active one, which Cloudflare would
// use.
func (c *Client) PlanZoneEnable(ctx context.Context, r ZoneEnableRequest) (*ZoneEnablePlan, error) {
	if err := checkCA(r.CACert); err != nil {
		return nil, err
	}
	zone, err := c.readZone(ctx, r.CACert)
	if err != nil {
		return nil, err
	}
	if !zone.Enabled {
		if _, err := enableTarget(zone, r.CACert); err != nil {
			return nil, err
		}
	}
	return &ZoneEnablePlan{client: c, zone: zone, ca: r.CACert}, nil
}

// enableTarget returns the certificate Cloudflare would use once zone-level
// AOP is enabled, if the CA signed it.
func enableTarget(zone *ZoneStatusReport, ca *x509.Certificate) (*CertificateInfo, error) {
	newest, ok := zone.NewestActive()
	if !ok {
		return nil, errors.New("cannot tell which active zone-level certificate Cloudflare would use: their uploaded_on values are missing, unreadable or equal")
	}
	if newest == nil {
		return nil, ErrNoActiveCertificate
	}
	if _, err := certSignedBy(&newest.Certificate, ca); err != nil {
		return nil, err
	}
	return newest, nil
}

// Zone returns a copy of the zone-level setting and certificates, as
// planned. When Enabled is set, Apply changes nothing. Otherwise its
// NewestActive method returns the certificate Cloudflare will use.
func (p *ZoneEnablePlan) Zone() *ZoneStatusReport {
	return p.zone.clone()
}

// Apply enables zone-level AOP, unless it was enabled when planned, and
// reads the setting back. Just before the change, it reads the zone again
// and fails unless the certificate Cloudflare would use is still the
// planned one. Without a deadline on ctx, the reads have no time limit.
func (p *ZoneEnablePlan) Apply(ctx context.Context) error {
	if !p.applied.CompareAndSwap(false, true) {
		return ErrPlanApplied
	}
	if p.zone.Enabled {
		return nil
	}
	planned, _ := p.zone.NewestActive()
	c := p.client
	zone, err := c.readZone(ctx, p.ca)
	if err != nil {
		return err
	}
	if !zone.Enabled {
		target, err := enableTarget(zone, p.ca)
		if err != nil {
			return err
		}
		if target.ID != planned.ID {
			return fmt.Errorf("the newest active zone-level certificate changed from %s to %s since the plan", planned.ID, target.ID)
		}
		if err := c.cf.enableZoneSetting(ctx); err != nil {
			return fmt.Errorf("enable zone-level AOP: %w", err)
		}
	}
	enabled, err := c.cf.getZoneSetting(ctx)
	if err != nil {
		return fmt.Errorf("read zone-level AOP setting back: %w", err)
	}
	if !enabled {
		return errors.New("zone-level AOP still reads as disabled")
	}
	return nil
}
