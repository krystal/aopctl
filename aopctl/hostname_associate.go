package aopctl

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"sync/atomic"
)

// HostnameAssociateRequest names an existing certificate and the hostnames
// to point at it, for example to resume or roll back an issue.
type HostnameAssociateRequest struct {
	// CACert must have signed the certificate.
	CACert *x509.Certificate
	CertID string
	// Hostnames are normalized with NormalizeHostnames, and there must be
	// one to MaxHostnames.
	Hostnames []string
}

// HostnameAssociatePlan is an association change, checked against the
// zone. Its accessors return copies, and Apply acts only on what the plan
// captured.
type HostnameAssociatePlan struct {
	client  *Client
	certID  string
	hosts   []string
	current map[string]*Association
	applied atomic.Bool
}

// CertID returns the certificate the hostnames will point at.
func (p *HostnameAssociatePlan) CertID() string { return p.certID }

// Hostnames returns the normalized hostnames.
func (p *HostnameAssociatePlan) Hostnames() []string { return slices.Clone(p.hosts) }

// Current returns each hostname's association when planned. A nil value
// means none.
func (p *HostnameAssociatePlan) Current() map[string]*Association {
	return cloneAssociations(p.current)
}

// PlanHostnameAssociate reads the certificate and the hostnames'
// associations. It fails without changing anything unless the CA signed
// the certificate and it is active, or when a hostname has AOP disabled.
func (c *Client) PlanHostnameAssociate(ctx context.Context, r HostnameAssociateRequest) (*HostnameAssociatePlan, error) {
	if err := checkCA(r.CACert); err != nil {
		return nil, err
	}
	if err := checkHostnameCertID(r.CertID); err != nil {
		return nil, err
	}
	hosts, err := requireHostnames(r.Hostnames)
	if err != nil {
		return nil, err
	}

	cert, err := c.cf.getCert(ctx, r.CertID)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", r.CertID, err)
	}
	if _, err := certSignedBy(cert, r.CACert); err != nil {
		return nil, err
	}
	if cert.Status != statusActive {
		return nil, fmt.Errorf("certificate %s is %s, not %s", r.CertID, cert.Status, statusActive)
	}
	current, err := c.readAssociations(ctx, hosts)
	if err != nil {
		return nil, err
	}
	if err := refuseDisabled(hosts, current); err != nil {
		return nil, err
	}
	return &HostnameAssociatePlan{client: c, certID: r.CertID, hosts: hosts, current: current}, nil
}

// Apply points every hostname at the certificate and waits for each
// association to become active. Without a deadline on ctx, it polls with no
// time limit.
func (p *HostnameAssociatePlan) Apply(ctx context.Context) error {
	if !p.applied.CompareAndSwap(false, true) {
		return ErrPlanApplied
	}
	if err := p.client.cf.associate(ctx, p.certID, p.hosts); err != nil {
		return fmt.Errorf("associate hostnames: %w", err)
	}
	return p.client.waitForAssociations(ctx, p.certID, p.hosts, map[string]*Association{})
}
