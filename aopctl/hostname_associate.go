package aopctl

import (
	"context"
	"crypto/x509"
	"fmt"
)

// HostnameAssociateRequest names an existing certificate and the hostnames
// to point at it, for example to resume or roll back an issue.
type HostnameAssociateRequest struct {
	// CACert must have signed the certificate.
	CACert *x509.Certificate
	CertID string
	// Hostnames are normalized with NormalizeHostnames.
	Hostnames []string
}

// HostnameAssociatePlan is an association change, checked against the zone.
type HostnameAssociatePlan struct {
	CertID    string
	Hostnames []string
	// Current holds each hostname's association when planned. A nil value
	// means none.
	Current map[string]*Association

	client  *Client
	applied bool
}

// PlanHostnameAssociate reads the certificate and the hostnames'
// associations. It fails without changing anything unless the CA signed
// the certificate and it is active, or when a hostname has AOP disabled.
func (c *Client) PlanHostnameAssociate(ctx context.Context, r HostnameAssociateRequest) (*HostnameAssociatePlan, error) {
	if err := checkCA(r.CACert); err != nil {
		return nil, err
	}
	if err := checkCertID(r.CertID); err != nil {
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
	return &HostnameAssociatePlan{CertID: r.CertID, Hostnames: hosts, Current: current, client: c}, nil
}

// Apply points every hostname at the certificate and waits for each
// association to become active.
func (p *HostnameAssociatePlan) Apply(ctx context.Context) error {
	if p.applied {
		return ErrPlanApplied
	}
	p.applied = true
	if err := p.client.cf.associate(ctx, p.CertID, p.Hostnames); err != nil {
		return fmt.Errorf("associate hostnames: %w", err)
	}
	return p.client.waitForAssociations(ctx, p.CertID, p.Hostnames, map[string]*Association{})
}
