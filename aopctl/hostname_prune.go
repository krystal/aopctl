package aopctl

import (
	"context"
	"crypto/x509"
	"fmt"
)

// HostnamePruneRequest names the hostname certificates to delete and the
// hostnames to check before deleting them.
type HostnamePruneRequest struct {
	// CACert must have signed each certificate.
	CACert  *x509.Certificate
	CertIDs []string
	// Hostnames are normalized with NormalizeHostnames. Only these
	// hostnames are checked: another hostname may still use a certificate.
	Hostnames []string
	// Progress, when set, receives CertificateSkipped while planning and
	// CertificateRefused, CertificateDeleteFailed and CertificateDeleted
	// during Apply.
	Progress func(Event)
}

// HostnamePrunePlan lists the certificates to delete and those skipped.
type HostnamePrunePlan struct {
	Hostnames []string
	Targets   []PruneTarget
	// Skipped holds the certificates that will not be deleted, in the
	// order they were decided.
	Skipped []PruneSkip

	client   *Client
	progress func(Event)
	applied  bool
}

// PruneTarget is a certificate a prune deletes, or waits for.
type PruneTarget struct {
	Certificate
	X509 *x509.Certificate
	// PendingDeletion is set for a certificate already being deleted, which
	// gets no second delete request.
	PendingDeletion bool
}

// SkipReason says why a prune skips a certificate.
type SkipReason int

// The reasons a prune skips a certificate.
const (
	// SkipNotFound is a certificate the zone does not have.
	SkipNotFound SkipReason = iota + 1
	// SkipNotSigned is a certificate the CA did not sign, or that cannot
	// be parsed. PruneSkip.Err says which.
	SkipNotSigned
	// SkipAlreadyDeleted is a certificate already deleted.
	SkipAlreadyDeleted
	// SkipInUse is a certificate a listed hostname uses.
	SkipInUse
)

// PruneSkip is a certificate a prune will not delete.
type PruneSkip struct {
	CertID string
	Reason SkipReason
	// Hostnames lists the hostnames using the certificate, for SkipInUse.
	Hostnames []string
	// Err is a *NotSignedError or a parse error, for SkipNotSigned.
	Err error
}

// PruneResult reports what a prune's Apply did.
type PruneResult struct {
	Deleted    []string
	NotDeleted []PruneFailure
}

// PruneFailure is a target a prune did not delete.
type PruneFailure struct {
	CertID string
	// Hostnames lists the hostnames that came to use the certificate after
	// the plan. It is empty when Err is set.
	Hostnames []string
	Err       error
}

// PlanHostnamePrune reads each certificate and the hostnames' associations.
// It skips certificates that are missing, already deleted, not signed by
// the CA, or used by a listed hostname. A read that fails for another
// reason fails the plan.
func (c *Client) PlanHostnamePrune(ctx context.Context, r HostnamePruneRequest) (*HostnamePrunePlan, error) {
	if err := checkCA(r.CACert); err != nil {
		return nil, err
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range r.CertIDs {
		if err := checkHostnameCertID(id); err != nil {
			return nil, err
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	hosts, err := requireHostnames(r.Hostnames)
	if err != nil {
		return nil, err
	}

	p := &HostnamePrunePlan{Hostnames: hosts, client: c, progress: r.Progress}
	skip := func(s PruneSkip) {
		p.Skipped = append(p.Skipped, s)
		emit(p.progress, CertificateSkipped{PruneSkip: s})
	}
	var targets []PruneTarget
	for _, id := range ids {
		cert, err := c.cf.getCert(ctx, id)
		if isNotFound(err) {
			skip(PruneSkip{CertID: id, Reason: SkipNotFound})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read certificate %s: %w", id, err)
		}
		parsed, err := certSignedBy(cert, r.CACert)
		if err != nil {
			skip(PruneSkip{CertID: id, Reason: SkipNotSigned, Err: err})
			continue
		}
		switch cert.Status {
		case statusDeleted:
			skip(PruneSkip{CertID: id, Reason: SkipAlreadyDeleted})
			continue
		case statusPendingDeletion:
			targets = append(targets, PruneTarget{Certificate: *cert, X509: parsed, PendingDeletion: true})
			continue
		}
		targets = append(targets, PruneTarget{Certificate: *cert, X509: parsed})
	}

	assocs, err := c.readAssociations(ctx, hosts)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		if !t.PendingDeletion {
			if using := hostsUsing(hosts, assocs, t.ID); len(using) > 0 {
				skip(PruneSkip{CertID: t.ID, Reason: SkipInUse, Hostnames: using})
				continue
			}
		}
		p.Targets = append(p.Targets, t)
	}
	return p, nil
}

// Deletes returns the number of delete requests Apply would send, which
// excludes certificates already being deleted.
func (p *HostnamePrunePlan) Deletes() int {
	n := 0
	for _, t := range p.Targets {
		if !t.PendingDeletion {
			n++
		}
	}
	return n
}

// Apply deletes each target and waits for the deletion to finish. Just
// before each delete, it reads the hostnames' associations again and skips
// a certificate that came into use. It returns ErrNotAllDeleted, with the
// result, when a target was not deleted.
func (p *HostnamePrunePlan) Apply(ctx context.Context) (*PruneResult, error) {
	if p.applied {
		return nil, ErrPlanApplied
	}
	p.applied = true
	c := p.client

	res := &PruneResult{}
	failed := func(id string, err error) {
		res.NotDeleted = append(res.NotDeleted, PruneFailure{CertID: id, Err: err})
		emit(p.progress, CertificateDeleteFailed{CertID: id, Err: err})
	}
	for _, t := range p.Targets {
		id := t.ID
		if !t.PendingDeletion {
			// Catch a hostname pointed at this certificate after the plan.
			current, err := c.readAssociations(ctx, p.Hostnames)
			if err != nil {
				failed(id, err)
				continue
			}
			if using := hostsUsing(p.Hostnames, current, id); len(using) > 0 {
				res.NotDeleted = append(res.NotDeleted, PruneFailure{CertID: id, Hostnames: using})
				emit(p.progress, CertificateRefused{CertID: id, Hostnames: using})
				continue
			}
			if err := c.cf.deleteCert(ctx, id); err != nil {
				failed(id, err)
				continue
			}
		}
		if err := c.waitForDeletion(ctx, id); err != nil {
			failed(id, err)
			continue
		}
		res.Deleted = append(res.Deleted, id)
		emit(p.progress, CertificateDeleted{CertID: id})
	}
	if len(res.NotDeleted) > 0 {
		return res, ErrNotAllDeleted
	}
	return res, nil
}
